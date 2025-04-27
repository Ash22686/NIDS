# -------------------------------------
#           app.py (Modified for Real-time)
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

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_very_secret_key!' # Needed for SocketIO sessions
CORS(app, resources={r"/*": {"origins": "*"}}) # Allow all origins for SocketIO/API

# --- Initialize SocketIO ---
# Set async_mode='threading' as Scapy sniff might block. 'eventlet' or 'gevent' are alternatives if installed.
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')
print("SocketIO initialized.")

# --- Global state for sniffing thread ---
capture_thread = None
stop_event = threading.Event()
# Store client SIDs that are actively capturing
active_capture_sids = set()


# --- Configuration & Loading (Keep this section exactly the same) ---
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

# Define mapping from prediction index to name
attack_mapping = {
    0: 'Normal',
    1: 'DOS (Denial of Service)',
    2: 'PROBE (Probing Attack)',
    3: 'R2L (Remote to Local Attack)',
    4: 'U2R (User to Root Attack)'
}

# --- Load Model and Preprocessing Info (Keep this section exactly the same) ---
model = None
quantiles = None
dummy_columns_from_train = None
top_features = None
original_form_columns = [col for col in notebook_assigned_columns if col not in ['attack']]
num_expected_features = len(original_form_columns) # Should be 42

# ... (try...except block for loading model, features, quantiles, dummies - NO CHANGES) ...
try:
    # Load model
    with open('model_no_leak.pkl', 'rb') as f:
        model = pickle.load(f)
    print("Loaded model (model_no_leak.pkl) successfully.")

    # Load features
    with open('top_features_no_leak.pkl', 'rb') as f:
        top_features = pickle.load(f)
    print(f"Loaded top features ({len(top_features)}).")

    # Load training data for preprocessing info
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

    # Separate for quantiles and dummies
    train_num_orig = train_df_orig[numeric_var_names_from_notebook].copy()
    train_cat_for_dummies = train_df_orig[cat_var_names_for_ui_dummies].copy()

    # Calculate Quantiles
    print("Calculating quantiles...")
    quantiles = {col: {'lower': train_num_orig[col].quantile(0.01), 'upper': train_num_orig[col].quantile(0.99)}
                 for col in numeric_var_names_from_notebook if col in train_num_orig.columns}
    print("Calculated quantiles.")

    # Get Dummy Columns List
    print("Generating reference dummy columns...")
    train_dummies_ref = pd.get_dummies(train_cat_for_dummies, columns=cat_var_names_for_ui_dummies, prefix=cat_var_names_for_ui_dummies, drop_first=True)
    dummy_columns_from_train = train_dummies_ref.columns.tolist()
    print(f"Reference dummy columns ({len(dummy_columns_from_train)}).")

except FileNotFoundError as e:
    print(f"Error: Required file not found: {e}.") # Simplified error handling for brevity
except Exception as e:
    print(f"An unexpected error occurred during loading: {e}")
    traceback.print_exc()
    # Set variables to None if loading fails critically
    model = quantiles = dummy_columns_from_train = top_features = attack_mapping = None

# --- Preprocessing Functions (Keep these exactly the same) ---
# ... (outlier_capping, preprocess_input - NO CHANGES) ...
def outlier_capping(x, lower_quantile, upper_quantile):
    """Applies outlier capping based on pre-calculated quantiles."""
    if pd.isna(lower_quantile) or pd.isna(upper_quantile):
        return x
    return x.clip(lower=lower_quantile, upper=upper_quantile)

def preprocess_input(input_data):
    """
    Applies the full preprocessing pipeline to user input (provided as a dict).
    Matches the pipeline used for the non-leaky model training.
    Args:
        input_data (dict): Dictionary containing raw feature values.
                           Keys should match 'original_form_columns'.
    Returns:
        pd.DataFrame: Processed data ready for prediction.
    """
    if not quantiles or not dummy_columns_from_train or not top_features or not model:
         raise ValueError("Preprocessing information or model not loaded correctly.")

    # print("Starting preprocessing for input...") # Less verbose logging for API
    try:
        # 1. Create DataFrame
        input_df = pd.DataFrame([input_data])

        # 2. Ensure columns & reorder
        try:
            input_df = input_df[original_form_columns]
        except KeyError as e:
            missing_cols = set(original_form_columns) - set(input_df.columns)
            raise ValueError(f"Input data dictionary is missing expected feature columns: {missing_cols}") from e

        # 3. Separate numeric/categorical
        input_num = input_df[numeric_var_names_from_notebook].copy()
        input_cat = input_df[cat_var_names_for_ui_dummies].copy()

        # 4. Type Conversion
        # print("Preprocessing: Converting numeric inputs...")
        for col in numeric_var_names_from_notebook:
            if col in input_num.columns:
                 input_num[col] = pd.to_numeric(input_num[col], errors='coerce')
            else:
                 raise ValueError(f"Expected numeric column '{col}' not found in input_num DataFrame.")
        if input_num.isnull().any().any():
            failed_cols = input_num.columns[input_num.isnull().any()].tolist()
            raise ValueError(f"Invalid non-numeric value provided for numeric feature(s): {failed_cols}")

        # 5. Outlier Capping
        # print("Preprocessing: Applying outlier capping...")
        for col in numeric_var_names_from_notebook:
            if col in quantiles:
                 input_num[col] = outlier_capping(input_num[col],
                                                   quantiles[col]['lower'],
                                                   quantiles[col]['upper'])

        # 6. Create Dummies
        # print("Preprocessing: Creating dummy variables...")
        input_dummies = pd.get_dummies(input_cat, columns=cat_var_names_for_ui_dummies, prefix=cat_var_names_for_ui_dummies, drop_first=True)

        # 7. Align Dummies
        # print("Preprocessing: Aligning dummy columns...")
        input_dummies_aligned = input_dummies.reindex(columns=dummy_columns_from_train, fill_value=0)

        # 8. Combine
        # print("Preprocessing: Combining...")
        processed_df = pd.concat([input_num, input_dummies_aligned], axis=1)

        # 9. Select Top Features
        # print(f"Preprocessing: Selecting {len(top_features)} top features...")
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


# --- Helper Function for Prediction from CSV string ---
def _perform_prediction(csv_string):
    # ... (This remains the same, used by the file upload API) ...
    if not csv_string:
        raise ValueError("Input cannot be empty.")

    values = [v.strip() for v in csv_string.split(',')]

    if len(values) != num_expected_features:
        raise ValueError(f"Incorrect number of features. Expected {num_expected_features}, got {len(values)}.")

    # Create dict using the 42 expected columns (excluding 'attack')
    raw_input_data = dict(zip(original_form_columns, values))
    processed_input = preprocess_input(raw_input_data)
    prediction = model.predict(processed_input)
    predicted_class_index = int(prediction[0])
    prediction_result = attack_mapping.get(predicted_class_index, f"Unknown ({predicted_class_index})")

    return prediction_result

# --- Helper Function to Simulate Features from Packet ---
def _simulate_features_from_packet(packet):
    """
    !!! SIMULATION ONLY !!!
    Creates a dictionary with 42 features based on minimal packet info.
    This is NOT accurate feature extraction for the NSL-KDD model.
    """
    # Default values (mostly zeros or common values)
    features = {col: 0 for col in original_form_columns} # Start with all zeros

    # Basic overrides based on packet layers (if present)
    proto = 'unknown'
    service = 'other' # Default service
    flag = 'SF'       # Default flag (Established) - highly speculative
    pkt_len = len(packet)

    if packet.haslayer(IP):
        ip_layer = packet.getlayer(IP)
        features['src_bytes'] = ip_layer.len # Use total IP length as approximation
        features['dst_bytes'] = 0 # Can't easily determine response bytes from one packet

        if packet.haslayer(TCP):
            proto = 'tcp'
            tcp_layer = packet.getlayer(TCP)
            # Map common TCP ports to service names (very basic)
            if tcp_layer.dport == 80 or tcp_layer.sport == 80: service = 'http'
            elif tcp_layer.dport == 443 or tcp_layer.sport == 443: service = 'https' # Note: KDD uses 'http' often even for 443
            elif tcp_layer.dport == 21 or tcp_layer.sport == 21: service = 'ftp'
            elif tcp_layer.dport == 22 or tcp_layer.sport == 22: service = 'ssh'
            elif tcp_layer.dport == 23 or tcp_layer.sport == 23: service = 'telnet'
            elif tcp_layer.dport == 25 or tcp_layer.sport == 25: service = 'smtp'
            elif tcp_layer.dport == 53 or tcp_layer.sport == 53: service = 'domain_u' # Often DNS over TCP
            # Simplistic flag mapping (needs proper state machine in reality)
            if tcp_layer.flags == 'S': flag = 'S0' # SYN only
            elif tcp_layer.flags == 'R': flag = 'REJ' # Reset
            # Add more flag mappings if needed (e.g., FIN -> SF/SH, etc.)
            features['logged_in'] = 1 if service not in ['http', 'https', 'other'] else 0 # Wild guess

        elif packet.haslayer(UDP):
            proto = 'udp'
            udp_layer = packet.getlayer(UDP)
            if udp_layer.dport == 53 or udp_layer.sport == 53: service = 'domain_u' # DNS
            elif udp_layer.dport == 67 or udp_layer.dport == 68: service = 'dhcp' # Using KDD 'other' often
            elif udp_layer.dport == 161 or udp_layer.sport == 161: service = 'snmp' # Using KDD 'private' often
            flag = 'SF' # UDP doesn't have flags like TCP in KDD sense

        elif packet.haslayer(ICMP):
            proto = 'icmp'
            service = 'ecr_i' # Example: Echo request (ping)
            flag = 'SF'

    # Assign the determined/default categorical values
    features['protocol_type'] = proto
    features['service'] = service
    features['flag'] = flag

    # Set some common default rates/counts (highly inaccurate)
    features['duration'] = 0
    features['count'] = 1
    features['srv_count'] = 1
    features['dst_host_count'] = 1
    features['dst_host_srv_count'] = 1
    features['same_srv_rate'] = 1.00
    features['dst_host_same_srv_rate'] = 1.00
    features['last_flag'] = 21 # A common value, might need adjustment

    # Ensure all original_form_columns are present
    final_features = {col: features.get(col, 0) for col in original_form_columns}

    # Convert features to strings as expected by preprocess_input via _perform_packet_prediction
    for key in final_features:
        final_features[key] = str(final_features[key])

    return final_features


# --- Helper Function for Prediction from Packet Data (using simulation) ---
def _perform_packet_prediction(feature_dict):
    """Takes a dictionary of SIMULATED features, preprocesses, predicts, and maps."""
    if not model:
        raise ValueError("Model not loaded.")
    try:
        processed_input = preprocess_input(feature_dict) # Pass the dict directly
        prediction = model.predict(processed_input)
        predicted_class_index = int(prediction[0])
        prediction_result = attack_mapping.get(predicted_class_index, f"Unknown ({predicted_class_index})")
        return prediction_result
    except Exception as e:
        print(f"Error during packet prediction: {e}")
        traceback.print_exc()
        raise # Re-raise the exception


# --- Packet Processing Callback for Scapy ---
def process_packet(packet):
    """Callback function for scapy's sniff(). Simulates features and emits prediction."""
    # Check if anyone is still listening before processing
    if not active_capture_sids:
        print("No active clients, stopping packet processing in callback.")
        return # Exit if no clients are connected to capture

    client_sid = next(iter(active_capture_sids)) # Get one SID to send to (simplistic for now)
    if not client_sid:
        return

    print(f"Packet captured: {packet.summary()}") # Log basic packet info
    try:
        # 1. Simulate Features
        simulated_features = _simulate_features_from_packet(packet)

        # 2. Perform Prediction
        prediction = _perform_packet_prediction(simulated_features)
        print(f"Packet Prediction: {prediction}")

        # 3. Emit Result via WebSocket to the specific client
        # Include some basic packet info for context
        packet_info = packet.summary()
        socketio.emit('capture_result', {
            'prediction': prediction,
            'packet_summary': packet_info,
            'timestamp': time.time()
        }, room=client_sid) # Send only to the requesting client

    except ValueError as e:
        print(f"ValueError in process_packet: {e}")
        socketio.emit('capture_error', {'error': str(e)}, room=client_sid)
    except Exception as e:
        print(f"Unexpected error processing packet: {e}")
        traceback.print_exc()
        socketio.emit('capture_error', {'error': 'An unexpected error occurred during packet processing.'}, room=client_sid)


# --- Background Sniffing Task ---
def sniffing_task(interface_name, sid):
    """Runs scapy.sniff in a loop until stop_event is set."""
    global stop_event
    print(f"Starting sniffing thread for SID: {sid} on interface: {interface_name}")
    try:
        # Check for root privileges (Linux/macOS specific check)
        if os.name == 'posix' and os.geteuid() != 0:
             raise PermissionError("Packet sniffing requires root privileges. Run the script with sudo.")
        # Add Windows check if needed (e.g., using ctypes and IsUserAnAdmin)

        # Ensure Scapy is available before trying to sniff
        if not SCAPY_AVAILABLE:
            raise ImportError("Scapy is not available or failed to import. Cannot start sniffing.")

        # Sniff indefinitely, stopping when stop_event is set
        # 'store=0' prevents storing packets in memory
        # 'prn' calls process_packet for each sniffed packet
        # 'stop_filter' checks the stop_event after each packet
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
        # Clean up SID when thread finishes
        if sid in active_capture_sids:
            active_capture_sids.remove(sid)
        # Ensure stop event is set in case of error exit
        stop_event.set()


# --- SocketIO Event Handlers ---
@socketio.on('connect')
def handle_connect():
    print(f"Client connected: {request.sid}")
    # Check if model is loaded on connect
    if model is None or attack_mapping is None:
        emit('server_error', {'error': 'Server model not loaded correctly. Analysis unavailable.'})

# REVISED DISCONNECT HANDLER
@socketio.on('disconnect')
def handle_disconnect():
    print(f"Client disconnected: {request.sid}")
    global capture_thread, stop_event

    # Check if a capture thread might be running that needs stopping.
    # This is simplified for one global thread.
    if capture_thread and capture_thread.is_alive():
         # Signal the potentially running thread to stop.
         # The thread itself will remove its SID from active_capture_sids in its finally block.
        print(f"Signaling capture thread to stop due to client {request.sid} disconnect.")
        # Set the event only if it's not already set to avoid redundant logging etc.
        if not stop_event.is_set():
            stop_event.set()
    else:
         print(f"Client {request.sid} disconnected, no active capture thread found or thread already stopping/stopped.")

    # DO NOT try to remove SID from active_capture_sids here.
    # DO NOT clear stop_event here (it gets cleared when starting a new capture).
    # DO NOT try to join the thread here (can block the disconnect handler).

@socketio.on('start_capture')
def handle_start_capture(data):
    # ... (keep existing start logic, ensure it clears stop_event) ...
    global capture_thread, stop_event, active_capture_sids

    if model is None:
        emit('capture_error', {'error': 'Model not loaded, cannot start capture.'})
        return
    if capture_thread and capture_thread.is_alive():
        emit('capture_error', {'error': 'Another capture is already in progress.'})
        return

    interface = data.get('interface') if isinstance(data, dict) else None
    print(f"Received start_capture request from {request.sid} for interface: {interface}")

    active_capture_sids.add(request.sid)
    stop_event.clear() # <--- Make sure this is cleared here!
    capture_thread = threading.Thread(target=sniffing_task, args=(interface, request.sid), daemon=True)
    capture_thread.start()
    emit('capture_started', {'message': f'Real-time capture started on interface: {interface or "default"}.'}) # Adjusted message
    print("Capture thread started.")


@socketio.on('stop_capture')
def handle_stop_capture():
    # ... (keep existing stop logic) ...
    global capture_thread, stop_event, active_capture_sids
    print(f"Received stop_capture request from {request.sid}")

    if capture_thread and capture_thread.is_alive():
        if not stop_event.is_set():
            stop_event.set() # Signal the thread to stop sniffing
        # Don't join here, let the thread finish and clean up
        print("Stop event set for capture thread via request.")
        emit('capture_stopped', {'message': 'Stop signal sent to real-time capture.'}) # Indicate signal sent
    else:
        print("No active capture thread to stop.")
        emit('capture_stopped', {'message': 'No capture was active.'})

    # Clean up SID regardless
    if request.sid in active_capture_sids:
        active_capture_sids.remove(request.sid)
    capture_thread = None
    stop_event.clear() # Reset for next potential capture


# --- Flask HTTP Routes ---

@app.route('/', methods=['GET'])
def index_page():
    """Serves the main HTML page (can be minimal if UI is pure React)."""
    server_error = None
    if model is None or attack_mapping is None:
         server_error = "Server configuration error: Model or preprocessing info not loaded."
    # If using React for UI, this might just return a basic template or redirect.
    # For simplicity, let's assume it could still serve a basic page.
    return render_template('index.html', error=server_error)


# --- API Endpoint for File Upload (remains the same) ---
@app.route('/api/analyze', methods=['POST'])
def analyze_api():
    """ API endpoint to analyze CSV data sent as JSON (File Upload). """
    print("\n--- File Upload API Request Received ---")
    # ... (Keep the existing implementation of this function exactly the same) ...
    if model is None or attack_mapping is None or top_features is None or quantiles is None or dummy_columns_from_train is None:
        print("API Error: Server not ready (model/data missing).")
        return jsonify({"error": "Server configuration error. Please check logs."}), 500

    if not request.is_json:
        print("API Error: Request Content-Type was not application/json.")
        return jsonify({"error": "Request must be JSON."}), 415 # Unsupported media type

    data = request.get_json()
    if not data or 'csv_input' not in data:
        print("API Error: Missing 'csv_input' in JSON payload.")
        return jsonify({"error": "Missing 'csv_input' field in JSON payload."}), 400 # Bad request

    csv_input_string = data['csv_input'].strip()
    print(f"API Received CSV string: '{csv_input_string[:100]}...'")

    try:
        # Use the helper function for the core logic
        prediction_result = _perform_prediction(csv_input_string)
        print(f"API Prediction: {prediction_result}")
        return jsonify({"prediction": prediction_result}), 200 # OK

    except ValueError as e: # Catch specific errors from validation or preprocessing
        print(f"API ValueError: {e}")
        return jsonify({"error": str(e)}), 400 # Bad request
    except Exception as e:
        print(f"API Exception: {e}")
        traceback.print_exc() # Log the full traceback
        return jsonify({"error": "An internal server error occurred during processing."}), 500 # Internal Server Error


# --- Run the App with SocketIO ---
if __name__ == '__main__':
    print("Starting Flask-SocketIO server...")
    # Check model readiness
    if model is None or quantiles is None or dummy_columns_from_train is None or top_features is None:
        print("WARNING: Model or critical preprocessing info failed to load. Check logs above.")
        print("Analysis features will be unavailable or may fail.")
    else:
        print("Model and preprocessing info appear loaded successfully.")
        print(f"File Upload API expecting {num_expected_features} comma-separated features.")

    if not SCAPY_AVAILABLE:
         print("WARNING: Scapy not installed or failed to load. Real-time analysis feature disabled.")
    elif os.name == 'posix' and os.geteuid() != 0:
         print("WARNING: Script not run as root. Real-time packet sniffing will likely fail due to permissions.")
    elif SCAPY_AVAILABLE:
         print("Scapy is available. Real-time analysis enabled (requires root/admin privileges).")

    # Use socketio.run() instead of app.run()
    # Set host='0.0.0.0' to make it accessible on the network
    # debug=True enables auto-reloading BUT can cause issues with background threads/SocketIO in some cases.
    # use_reloader=False is often safer when using background threads/SocketIO.
    socketio.run(app, host='0.0.0.0', port=5000, debug=False, use_reloader=False, allow_unsafe_werkzeug=True)
    # Note: allow_unsafe_werkzeug=True is needed for debug=True with SocketIO >= 5. Use with caution.
    # For production, use a proper WSGI server like gunicorn with eventlet or gevent workers.
    # Example: gunicorn --worker-class eventlet -w 1 app:app