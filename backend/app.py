# -------------------------------------
#           app.py (MODIFIED for 2 Models)
# -------------------------------------
import numpy as np
import pandas as pd
import pickle
import traceback
import csv
import threading # For background sniffing
import time
import os # To check for root privileges

from flask import Flask, request, render_template, jsonify
from flask_cors import CORS
from flask_socketio import SocketIO, emit, disconnect # Import SocketIO

# --- Try importing Scapy ---
try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP
    SCAPY_AVAILABLE = True
    print("Scapy imported successfully.")
except ImportError:
    SCAPY_AVAILABLE = False
    print("WARNING: Scapy is not installed. Real-time analysis will be disabled.")
    print("Install it using: pip install scapy")
except OSError as e:
    # Catch potential errors like 'libpcap not found' on import
    SCAPY_AVAILABLE = False
    print(f"WARNING: Error importing Scapy ({e}). Real-time analysis might fail.")
    print("Ensure libpcap/Npcap is installed correctly.")

# --- Try importing TensorFlow ---
try:
    import tensorflow as tf
    # Optional: Configure GPU memory growth if using GPU
    # gpus = tf.config.experimental.list_physical_devices('GPU')
    # if gpus:
    #     try:
    #         for gpu in gpus:
    #             tf.config.experimental.set_memory_growth(gpu, True)
    #     except RuntimeError as e:
    #         print(f"Warning: Could not set memory growth for GPU: {e}")
    TENSORFLOW_AVAILABLE = True
    print("TensorFlow imported successfully.")
except ImportError:
    TENSORFLOW_AVAILABLE = False
    print("WARNING: TensorFlow is not installed. Anomaly detection model cannot be loaded.")
    print("Install it using: pip install tensorflow")


app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_very_secret_key!' # Needed for SocketIO sessions
CORS(app, resources={r"/": {"origins": ""}}) # Allow all origins for SocketIO/API

# --- Initialize SocketIO ---
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')
print("SocketIO initialized.")

# --- Global state for sniffing thread ---
capture_thread = None
stop_event = threading.Event()
active_capture_sids = set()


# --- Configuration & Loading ---
# ... (notebook_assigned_columns, numeric_var_names_from_notebook, etc. - NO CHANGES) ...
# Define column names EXACTLY as assigned in the training notebook (43 columns)
notebook_assigned_columns = [
    "duration", "protocol_type", "service", "flag", "src_bytes", "dst_bytes", "land",
    "wrong_fragment", "urgent", "hot", "num_failed_logins", "logged_in", "num_compromised",
    "root_shell", "su_attempted", "num_root", "num_file_creations", "num_shells",
    "num_access_files", "num_outbound_cmds", "is_host_login", "is_guest_login", "count",
    "srv_count", "serror_rate", "srv_serror_rate", "rerror_rate", "srv_rerror_rate",
    "same_srv_rate", "diff_srv_rate", "srv_diff_host_rate", "dst_host_count",
    "dst_host_srv_count", "dst_host_same_srv_rate", "dst_host_diff_srv_rate",
    "dst_host_same_src_port_rate", "dst_host_srv_diff_host_rate", "dst_host_serror_rate",
    "dst_host_srv_serror_rate", "dst_host_rerror_rate", "dst_host_srv_rerror_rate",
    "attack", # Second to last column as per notebook
    "last_flag" # Very last column as per notebook
]

# Define numeric feature names based on the notebook's dtypes
numeric_var_names_from_notebook = [
    'duration', 'src_bytes', 'dst_bytes', 'land', 'wrong_fragment', 'urgent', 'hot',
    'num_failed_logins', 'logged_in', 'num_compromised', 'root_shell', 'su_attempted',
    'num_root', 'num_file_creations', 'num_shells', 'num_access_files',
    'num_outbound_cmds', 'is_host_login', 'is_guest_login', 'count', 'srv_count',
    'serror_rate', 'srv_serror_rate', 'rerror_rate', 'srv_rerror_rate', 'same_srv_rate',
    'diff_srv_rate', 'srv_diff_host_rate', 'dst_host_count', 'dst_host_srv_count',
    'dst_host_same_srv_rate', 'dst_host_diff_srv_rate', 'dst_host_same_src_port_rate',
    'dst_host_srv_diff_host_rate', 'dst_host_serror_rate', 'dst_host_srv_serror_rate',
    'dst_host_rerror_rate', 'dst_host_srv_rerror_rate',
    'last_flag'
]
# Define categorical feature names RELEVANT FOR UI INPUT (excluding 'attack')
cat_var_names_for_ui_dummies = ['protocol_type', 'service', 'flag']

# Define mapping from prediction index to name (for the primary model)
attack_mapping = {
    0: 'Normal',
    1: 'DOS (Denial of Service)',
    2: 'PROBE (Probing Attack)',
    3: 'R2L (Remote to Local Attack)',
    4: 'U2R (User to Root Attack)'
}

# --- Load Models and Preprocessing Info ---
model = None # Primary signature model
anomaly_model = None # Secondary anomaly model
quantiles = None
dummy_columns_from_train = None
top_features = None
original_form_columns = [col for col in notebook_assigned_columns if col not in ['attack']]
num_expected_features = len(original_form_columns) # Should be 42

try:
    # Load PRIMARY model (Signature-based)
    with open('model_no_leak.pkl', 'rb') as f:
        model = pickle.load(f)
    print("Loaded primary model (model_no_leak.pkl) successfully.")

    # Load SECONDARY model (Anomaly-based)
    if TENSORFLOW_AVAILABLE:
        try:
            anomaly_model = tf.keras.models.load_model('anomalymodel.h5')
            print("Loaded anomaly model (anomalymodel.h5) successfully.")
            # Optional: Print model summary
            # anomaly_model.summary()
        except Exception as e:
            print(f"Error loading anomaly model 'anomalymodel.h5': {e}")
            traceback.print_exc()
            anomaly_model = None # Ensure it's None if loading fails
    else:
        print("Skipping anomaly model loading because TensorFlow is not available.")


    # --- Load features, quantiles, dummies (No changes needed here) ---
    with open('top_features_no_leak.pkl', 'rb') as f:
        top_features = pickle.load(f)
    print(f"Loaded top features ({len(top_features)}).")

    print("Loading training data for preprocessing info...")
    train_df_orig = pd.read_csv(
        'NSL_Dataset/Train.txt', sep=',', header=None, names=notebook_assigned_columns
    )
    print(f"Loaded {len(train_df_orig)} rows from Train.txt")

    # Coerce numeric and handle errors
    for col in numeric_var_names_from_notebook:
        if col in train_df_orig.columns:
            train_df_orig[col] = pd.to_numeric(train_df_orig[col], errors='coerce')
    rows_before = len(train_df_orig)
    train_df_orig.dropna(subset=numeric_var_names_from_notebook, inplace=True)
    rows_after = len(train_df_orig)
    if rows_before > rows_after: print(f"Warning: Dropped {rows_before - rows_after} rows during loading.")
    if rows_after == 0: raise ValueError("All rows dropped after numeric conversion.")

    train_num_orig = train_df_orig[numeric_var_names_from_notebook].copy()
    train_cat_for_dummies = train_df_orig[cat_var_names_for_ui_dummies].copy()

    print("Calculating quantiles...")
    quantiles = {col: {'lower': train_num_orig[col].quantile(0.01), 'upper': train_num_orig[col].quantile(0.99)}
                 for col in numeric_var_names_from_notebook if col in train_num_orig.columns}
    print("Calculated quantiles.")

    print("Generating reference dummy columns...")
    train_dummies_ref = pd.get_dummies(train_cat_for_dummies, columns=cat_var_names_for_ui_dummies, prefix=cat_var_names_for_ui_dummies, drop_first=True)
    dummy_columns_from_train = train_dummies_ref.columns.tolist()
    print(f"Reference dummy columns ({len(dummy_columns_from_train)}).")

except FileNotFoundError as e:
    print(f"Error: Required file not found: {e}.")
    if 'model_no_leak.pkl' in str(e): model = None
    if 'anomalymodel.h5' in str(e): anomaly_model = None
    if 'top_features_no_leak.pkl' in str(e): top_features = None
except Exception as e:
    print(f"An unexpected error occurred during loading: {e}")
    traceback.print_exc()
    model = anomaly_model = quantiles = dummy_columns_from_train = top_features = attack_mapping = None

# --- Preprocessing Functions (Keep these exactly the same) ---
# ... (outlier_capping, preprocess_input - NO CHANGES NEEDED) ...
# Assume preprocess_input works for BOTH models
def outlier_capping(x, lower_quantile, upper_quantile):
    """Applies outlier capping based on pre-calculated quantiles."""
    if pd.isna(lower_quantile) or pd.isna(upper_quantile):
        return x
    return x.clip(lower=lower_quantile, upper=upper_quantile)

def preprocess_input(input_data):
    """
    Applies the full preprocessing pipeline to user input (provided as a dict).
    Matches the pipeline used for the non-leaky model training.
    ASSUMPTION: This pipeline is suitable for BOTH the primary and anomaly models.
    Args:
        input_data (dict): Dictionary containing raw feature values.
                           Keys should match 'original_form_columns'.
    Returns:
        pd.DataFrame: Processed data ready for prediction.
    """
    if not quantiles or not dummy_columns_from_train or not top_features:
         raise ValueError("Preprocessing information not loaded correctly.")

    # print("Starting preprocessing for input...") # Less verbose logging for API
    try:
        input_df = pd.DataFrame([input_data])
        try:
            input_df = input_df[original_form_columns]
        except KeyError as e:
            missing_cols = set(original_form_columns) - set(input_df.columns)
            raise ValueError(f"Input data dictionary is missing expected feature columns: {missing_cols}") from e

        input_num = input_df[numeric_var_names_from_notebook].copy()
        input_cat = input_df[cat_var_names_for_ui_dummies].copy()

        for col in numeric_var_names_from_notebook:
            if col in input_num.columns:
                 input_num[col] = pd.to_numeric(input_num[col], errors='coerce')
            else:
                 raise ValueError(f"Expected numeric column '{col}' not found in input_num DataFrame.")
        if input_num.isnull().any().any():
            failed_cols = input_num.columns[input_num.isnull().any()].tolist()
            raise ValueError(f"Invalid non-numeric value provided for numeric feature(s): {failed_cols}")

        for col in numeric_var_names_from_notebook:
            if col in quantiles:
                 input_num[col] = outlier_capping(input_num[col],
                                                   quantiles[col]['lower'],
                                                   quantiles[col]['upper'])

        input_dummies = pd.get_dummies(input_cat, columns=cat_var_names_for_ui_dummies, prefix=cat_var_names_for_ui_dummies, drop_first=True)
        input_dummies_aligned = input_dummies.reindex(columns=dummy_columns_from_train, fill_value=0)
        processed_df = pd.concat([input_num, input_dummies_aligned], axis=1)

        missing_model_features = set(top_features) - set(processed_df.columns)
        if missing_model_features:
            raise ValueError(f"Internal Error: Processed data missing model features: {missing_model_features}")
        final_input_df = processed_df[top_features]
        # print("Preprocessing completed.")
        return final_input_df

    except KeyError as e:
        raise ValueError(f"Missing expected column during preprocessing: {e}")
    except ValueError as e:
        raise # Re-raise specific ValueErrors
    except Exception as e:
        traceback.print_exc()
        raise ValueError("An unexpected error occurred during preprocessing.")


# --- Helper Function for Prediction from CSV string (File Upload - unchanged) ---
def _perform_prediction(csv_string):
    # This function is ONLY for the file upload endpoint and uses only the primary model.
    # It does NOT use the anomaly model.
    if not csv_string:
        raise ValueError("Input cannot be empty.")
    if not model:
        raise ValueError("Primary model not loaded.")

    values = [v.strip() for v in csv_string.split(',')]
    if len(values) != num_expected_features:
        raise ValueError(f"Incorrect number of features. Expected {num_expected_features}, got {len(values)}.")

    raw_input_data = dict(zip(original_form_columns, values))
    processed_input = preprocess_input(raw_input_data) # Use the shared preprocessor
    prediction = model.predict(processed_input)
    predicted_class_index = int(prediction[0])
    prediction_result = attack_mapping.get(predicted_class_index, f"Unknown ({predicted_class_index})")

    return prediction_result

# --- Helper Function to Simulate Features from Packet (unchanged) ---
def _simulate_features_from_packet(packet):
    """
    !!! SIMULATION ONLY !!! Creates a dictionary with 42 features.
    """
    # Default values
    features = {col: 0 for col in original_form_columns}
    proto, service, flag = 'unknown', 'other', 'SF'
    pkt_len = len(packet)

    if packet.haslayer(IP):
        ip_layer = packet.getlayer(IP)
        features['src_bytes'] = ip_layer.len
        features['dst_bytes'] = 0 # Approximation

        if packet.haslayer(TCP):
            proto = 'tcp'
            tcp_layer = packet.getlayer(TCP)
            dport, sport = tcp_layer.dport, tcp_layer.sport
            if dport == 80 or sport == 80: service = 'http'
            elif dport == 443 or sport == 443: service = 'http' # KDD often uses http for 443
            elif dport == 21 or sport == 21: service = 'ftp'
            elif dport == 22 or sport == 22: service = 'ssh'
            elif dport == 23 or sport == 23: service = 'telnet'
            elif dport == 25 or sport == 25: service = 'smtp'
            elif dport == 53 or sport == 53: service = 'domain_u'
            # Simplistic flag mapping
            if tcp_layer.flags == 'S': flag = 'S0'
            elif tcp_layer.flags == 'R': flag = 'REJ'
            # Wild guess for logged_in
            features['logged_in'] = 1 if service not in ['http', 'other'] else 0

        elif packet.haslayer(UDP):
            proto = 'udp'
            udp_layer = packet.getlayer(UDP)
            dport, sport = udp_layer.dport, udp_layer.sport
            if dport == 53 or sport == 53: service = 'domain_u'
            elif dport == 67 or dport == 68: service = 'other' # DHCP map
            elif dport == 161 or sport == 161: service = 'private' # SNMP map
            flag = 'SF'

        elif packet.haslayer(ICMP):
            proto = 'icmp'
            service = 'ecr_i' # Example: Echo request
            flag = 'SF'

    features['protocol_type'] = proto
    features['service'] = service
    features['flag'] = flag
    features['duration'] = 0
    features['count'] = 1
    features['srv_count'] = 1
    features['dst_host_count'] = 1
    features['dst_host_srv_count'] = 1
    features['same_srv_rate'] = 1.00
    features['dst_host_same_srv_rate'] = 1.00
    features['last_flag'] = 21 # Common value

    final_features = {col: features.get(col, 0) for col in original_form_columns}
    for key in final_features:
        final_features[key] = str(final_features[key]) # Convert all to string for preprocess_input
    return final_features


# --- Helper Function for Prediction from Packet Data (using simulation) ---
# --- MODIFIED to handle BOTH models ---
def _perform_packet_prediction(feature_dict):
    """
    Takes a dictionary of SIMULATED features, preprocesses, predicts with
    primary model, and conditionally predicts with anomaly model.
    Returns:
        tuple: (primary_prediction_str, anomaly_prediction_str_or_none)
    """
    if not model:
        raise ValueError("Primary model not loaded.")
    # Anomaly model check happens inside the conditional block

    primary_prediction_result = "Error"
    anomaly_prediction_result = None # Default to None (not run or not applicable)

    try:
        # 1. Preprocess ONCE (assuming suitable for both models)
        processed_input = preprocess_input(feature_dict)

        # 2. Predict with Primary Model (Signature-based)
        prediction_primary = model.predict(processed_input)
        predicted_class_index = int(prediction_primary[0])
        primary_prediction_result = attack_mapping.get(predicted_class_index, f"Unknown ({predicted_class_index})")

        # 3. Conditionally Predict with Anomaly Model
        if primary_prediction_result == 'Normal':
            if not anomaly_model:
                print("Anomaly model not loaded, skipping anomaly check for Normal packet.")
                anomaly_prediction_result = "N/A (Model Unloaded)"
            elif not TENSORFLOW_AVAILABLE:
                 anomaly_prediction_result = "N/A (TF Missing)"
            else:
                try:
                    # Predict using the SAME preprocessed input
                    # Keras predict often returns [[prob]] or [[class_idx]]
                    prediction_anomaly_raw = anomaly_model.predict(processed_input)
                    # --- MAP ANOMALY MODEL OUTPUT ---
                    # *ADJUST THIS MAPPING based on your anomaly model's output*
                    # Example 1: If it outputs class index (0=Normal, 1=Anomaly)
                    anomaly_class = np.argmax(prediction_anomaly_raw, axis=1)[0] # Get index of max value
                    if anomaly_class == 1: # Assuming 1 means anomaly
                        anomaly_prediction_result = "Anomalous"
                    else:
                        anomaly_prediction_result = "Normal (Anomaly Model)"

                    # Example 2: If it outputs a probability score (e.g., > 0.5 is anomaly)
                    # anomaly_score = prediction_anomaly_raw[0][0] # Assuming shape (1, 1)
                    # threshold = 0.5
                    # if anomaly_score >= threshold:
                    #      anomaly_prediction_result = f"Anomalous (Score: {anomaly_score:.2f})"
                    # else:
                    #      anomaly_prediction_result = f"Normal (Score: {anomaly_score:.2f})"
                    # --------------------------------

                except Exception as anomaly_e:
                    print(f"Error during anomaly model prediction: {anomaly_e}")
                    traceback.print_exc()
                    anomaly_prediction_result = "Error (Anomaly Check Failed)"

        # If primary prediction was not 'Normal', anomaly_prediction_result remains None

        return primary_prediction_result, anomaly_prediction_result

    except ValueError as e: # Catch preprocessing errors
        print(f"ValueError during preprocessing for packet prediction: {e}")
        raise # Re-raise to be caught in process_packet
    except Exception as e:
        print(f"Unexpected error during packet prediction: {e}")
        traceback.print_exc()
        raise # Re-raise


# --- Packet Processing Callback for Scapy ---
# --- MODIFIED to handle combined results ---
def process_packet(packet):
    """Callback function for scapy's sniff(). Simulates features, predicts, and emits results."""
    if not active_capture_sids:
        # print("No active clients, stopping packet processing in callback.") # Can be verbose
        return

    # Simplistic: Send to the first SID found. Refactor if multiple clients need independent streams.
    client_sid = next(iter(active_capture_sids), None)
    if not client_sid:
        return

    # print(f"Packet captured: {packet.summary()}") # Log basic packet info (can be verbose)
    try:
        # 1. Simulate Features
        simulated_features = _simulate_features_from_packet(packet)

        # 2. Perform Prediction (gets both results now)
        prediction_primary, prediction_anomaly = _perform_packet_prediction(simulated_features)
        print(f"Packet Prediction: Primary='{prediction_primary}', Anomaly='{prediction_anomaly}'")

        # 3. Emit Combined Result via WebSocket
        packet_info = packet.summary()
        socketio.emit('capture_result', {
            'prediction': prediction_primary,       # Result from model 1
            'anomaly_prediction': prediction_anomaly, # Result from model 2 (or None/NA/Error)
            'packet_summary': packet_info,
            'timestamp': time.time()
        }, room=client_sid)

    except ValueError as e: # Catch errors from preprocessing or prediction helpers
        print(f"ValueError in process_packet: {e}")
        socketio.emit('capture_error', {'error': str(e)}, room=client_sid)
    except Exception as e:
        print(f"Unexpected error processing packet: {e}")
        traceback.print_exc()
        socketio.emit('capture_error', {'error': 'An unexpected error occurred during packet processing.'}, room=client_sid)


# --- Background Sniffing Task (unchanged) ---
def sniffing_task(interface_name, sid):
    """Runs scapy.sniff in a loop until stop_event is set."""
    global stop_event
    print(f"Starting sniffing thread for SID: {sid} on interface: {interface_name}")
    try:
        # Check for root privileges (Linux/macOS specific check)
        if os.name == 'posix' and os.geteuid() != 0:
             raise PermissionError("Packet sniffing requires root privileges. Run the script with sudo.")

        if not SCAPY_AVAILABLE:
            raise ImportError("Scapy is not available or failed to import. Cannot start sniffing.")

        sniff(iface=interface_name, prn=process_packet, store=0, stop_filter=lambda p: stop_event.is_set())

    except PermissionError as e:
        print(f"PermissionError in sniffing_task: {e}")
        socketio.emit('capture_error', {'error': str(e)}, room=sid)
    except ImportError as e:
        print(f"ImportError in sniffing_task: {e}")
        socketio.emit('capture_error', {'error': str(e)}, room=sid)
    except OSError as e: # Catch potential Scapy/libpcap runtime errors
        print(f"OSError during sniff: {e}")
        socketio.emit('capture_error', {'error': f"Network interface error: {e}. Is '{interface_name}' correct and available?"}, room=sid)
    except Exception as e:
        print(f"Unexpected error in sniffing_task: {e}")
        traceback.print_exc()
        socketio.emit('capture_error', {'error': 'An unexpected error occurred during packet sniffing.'}, room=sid)
    finally:
        print(f"Sniffing thread stopped for SID: {sid}.")
        if sid in active_capture_sids:
            active_capture_sids.remove(sid)
        if not active_capture_sids: # If this was the last client, ensure stop event is set
             stop_event.set()


# --- SocketIO Event Handlers ---
@socketio.on('connect')
def handle_connect():
    print(f"Client connected: {request.sid}")
    # Check if models are loaded on connect
    error_msg = None
    if model is None:
        error_msg = 'Primary signature model not loaded. Analysis unavailable.'
    elif anomaly_model is None and TENSORFLOW_AVAILABLE: # Only warn if TF is installed but model failed
         error_msg = 'Anomaly detection model failed to load. Anomaly checks will be skipped.'
    elif not TENSORFLOW_AVAILABLE:
         error_msg = 'TensorFlow not found. Anomaly detection model is disabled.'

    if error_msg:
        print(f"Server Error on Connect: {error_msg}")
        emit('server_error', {'error': error_msg})

# --- Disconnect Handler (Revised - Simplified) ---
@socketio.on('disconnect')
def handle_disconnect():
    print(f"Client disconnected: {request.sid}")
    global capture_thread, stop_event

    # Remove disconnected client from active list
    if request.sid in active_capture_sids:
        active_capture_sids.remove(request.sid)
        print(f"Removed SID {request.sid} from active capture list.")

    # If no clients are left capturing, signal the thread to stop
    if not active_capture_sids and capture_thread and capture_thread.is_alive():
        if not stop_event.is_set():
            print("Last client disconnected, signaling capture thread to stop.")
            stop_event.set()
        # We don't join the thread here to avoid blocking disconnect

# --- Start Capture Handler ---
@socketio.on('start_capture')
def handle_start_capture(data):
    global capture_thread, stop_event, active_capture_sids

    # Check model readiness
    if model is None:
        emit('capture_error', {'error': 'Primary model not loaded, cannot start capture.'})
        return
    # Optionally check for anomaly model, but allow starting without it
    if anomaly_model is None:
         print("Warning: Anomaly model not loaded. Capture will proceed without anomaly checks.")
         # emit('capture_info', {'message': 'Anomaly model not loaded, anomaly checks disabled.'}) # Optional info message

    # Check if another capture (by any client) is running - simplified global thread model
    if capture_thread and capture_thread.is_alive():
        # Check if the requesting client is already considered active (e.g., browser refresh)
        if request.sid in active_capture_sids:
             print(f"SID {request.sid} is already in active capture list. Re-sending started message.")
             emit('capture_started', {'message': 'Capture is already running.'}) # Inform client it's running
             return # Don't start a new thread
        else:
            # This case shouldn't happen with the current simplified global thread,
            # but good to have a message if it did.
            emit('capture_error', {'error': 'A capture session is already in progress by another client.'})
            return

    interface = data.get('interface') if isinstance(data, dict) else None
    print(f"Received start_capture request from {request.sid} for interface: {interface}")

    # Start sniffing
    active_capture_sids.add(request.sid) # Add before starting thread
    stop_event.clear() # IMPORTANT: Clear the stop event for the new session
    capture_thread = threading.Thread(target=sniffing_task, args=(interface, request.sid), daemon=True)
    capture_thread.start()
    emit('capture_started', {'message': f'Real-time capture started on interface: {interface or "default"}.'})
    print(f"Capture thread started for SID: {request.sid}")


# --- Stop Capture Handler (Revised - Simpler Stop) ---
@socketio.on('stop_capture')
def handle_stop_capture():
    global capture_thread, stop_event, active_capture_sids
    print(f"Received stop_capture request from {request.sid}")

    # Remove this specific client from wanting capture
    if request.sid in active_capture_sids:
        active_capture_sids.remove(request.sid)
        print(f"Removed SID {request.sid} from active capture list on stop request.")

    # If no clients are left, or if the thread isn't running, stop it
    if not active_capture_sids and capture_thread and capture_thread.is_alive():
        if not stop_event.is_set():
            stop_event.set() # Signal the thread to stop sniffing
            print("Stop event set for capture thread via request (last client stopped).")
            emit('capture_stopped', {'message': 'Capture stopped.'})
        else:
            # Already stopping
            emit('capture_stopped', {'message': 'Capture is already stopping.'})

    elif not (capture_thread and capture_thread.is_alive()):
        print("No active capture thread to stop.")
        emit('capture_stopped', {'message': 'No capture was active.'})
        # Ensure state is clean if thread died unexpectedly
        active_capture_sids.clear()
        capture_thread = None
        stop_event.clear() # Okay to clear if definitely not running
    else:
        # Other clients are still active, just acknowledge this client stopped listening
        print(f"Client {request.sid} stopped listening, but other clients remain.")
        emit('capture_stopped', {'message': f'You stopped receiving data. Capture continues for other clients.'})


# --- Flask HTTP Routes ---

@app.route('/', methods=['GET'])
def index_page():
    """Serves the main HTML page."""
    server_error = None
    if model is None:
         server_error = "Server configuration error: Primary model not loaded."
    elif anomaly_model is None and TENSORFLOW_AVAILABLE:
        server_error = "Warning: Anomaly detection model failed to load."
    # Return a basic template or placeholder
    return render_template('index.html', error=server_error)


# --- API Endpoint for File Upload (remains the same - uses primary model only) ---
@app.route('/api/analyze', methods=['POST'])
def analyze_api():
    """ API endpoint to analyze CSV data sent as JSON (File Upload). """
    print("\n--- File Upload API Request Received ---")
    if model is None: # Only primary model is needed here
        print("API Error: Server not ready (primary model missing).")
        return jsonify({"error": "Server configuration error: Primary model missing."}), 500

    if not request.is_json:
        print("API Error: Request Content-Type was not application/json.")
        return jsonify({"error": "Request must be JSON."}), 415

    data = request.get_json()
    if not data or 'csv_input' not in data:
        print("API Error: Missing 'csv_input' in JSON payload.")
        return jsonify({"error": "Missing 'csv_input' field in JSON payload."}), 400

    csv_input_string = data['csv_input'].strip()
    print(f"API Received CSV string: '{csv_input_string[:100]}...'")

    try:
        # Use the helper function for the core logic (primary model only)
        prediction_result = _perform_prediction(csv_input_string)
        print(f"API Prediction: {prediction_result}")
        return jsonify({"prediction": prediction_result}), 200

    except ValueError as e: # Catch specific errors from validation or preprocessing
        print(f"API ValueError: {e}")
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        print(f"API Exception: {e}")
        traceback.print_exc() # Log the full traceback
        return jsonify({"error": "An internal server error occurred during processing."}), 500


# --- Run the App with SocketIO ---
if __name__ == '__main__':
    print("Starting Flask-SocketIO server...")
    # Check model readiness
    model_ready = True
    if model is None or quantiles is None or dummy_columns_from_train is None or top_features is None:
        print("CRITICAL WARNING: Primary model or critical preprocessing info failed to load. Check logs.")
        print("Core analysis features will be unavailable or may fail.")
        model_ready = False
    else:
        print("Primary model and preprocessing info appear loaded successfully.")
        print(f"File Upload API expecting {num_expected_features} comma-separated features.")

    if TENSORFLOW_AVAILABLE:
        if anomaly_model is None:
             print("WARNING: Anomaly detection model ('anomalymodel.h5') failed to load, but TensorFlow is installed.")
             print("Real-time analysis will proceed WITHOUT anomaly checks for 'Normal' packets.")
        else:
             print("Anomaly detection model ('anomalymodel.h5') loaded successfully.")
    else:
        print("INFO: TensorFlow not found. Anomaly detection model is disabled.")

    # Scapy checks
    if not SCAPY_AVAILABLE:
         print("WARNING: Scapy not installed or failed to load. Real-time analysis feature disabled.")
    elif os.name == 'posix' and os.geteuid() != 0:
         print("WARNING: Script not run as root. Real-time packet sniffing will likely fail due to permissions.")
    elif SCAPY_AVAILABLE:
         print("Scapy is available. Real-time analysis enabled (requires root/admin privileges).")

    if not model_ready:
        print("\n*** SERVER STARTING WITH CRITICAL ERRORS - Functionality will be limited. ***\n")

    socketio.run(app, host='0.0.0.0', port=5000, debug=False, use_reloader=False, allow_unsafe_werkzeug=True)