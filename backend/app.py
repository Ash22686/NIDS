# -------------------------------------
#           app.py (Complete)
# -------------------------------------
import numpy as np
import pandas as pd
import pickle
import traceback
import csv
import threading # For background sniffing
import time
import os # To check for root privileges
import io # For reading string as file
from collections import Counter # For counting predictions

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


app = Flask(__name__, template_folder='templates') # Specify template folder if needed
app.config['SECRET_KEY'] = 'your_very_secret_key!' # Needed for SocketIO sessions
CORS(app) # Allow all origins for SocketIO/API

# --- Initialize SocketIO ---
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')
print("SocketIO initialized.")

# --- Global state for sniffing thread ---
capture_thread = None
stop_event = threading.Event()
active_capture_sids = set()


# --- Configuration & Loading ---
# IMPORTANT: The uploaded CSV file MUST NOT have a header row and MUST
# have exactly these 43 columns in this order.
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
num_expected_file_columns = len(notebook_assigned_columns) # Should be 43

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

# Define mapping from prediction index to name (for the primary model) - Use shorter names
attack_mapping = {
    0: 'Normal',
    1: 'DoS',
    2: 'Probe',
    3: 'R2L',
    4: 'U2R'
}

# --- Load Models and Preprocessing Info ---
model = None # Primary signature model
anomaly_model = None # Secondary anomaly model
quantiles = None
dummy_columns_from_train = None
top_features = None
# --- Column list for the *model input* (42 features, excluding 'attack') ---
original_form_columns = [col for col in notebook_assigned_columns if col != 'attack']
num_expected_features_for_model = len(original_form_columns) # Should be 42

try:
    # Load PRIMARY model (Signature-based)
    # Make sure these paths are correct relative to where you run app.py
    model_path = 'model_no_leak.pkl'
    features_path = 'top_features_no_leak.pkl'
    train_data_path = 'NSL_Dataset/Train.txt'
    anomaly_model_path = 'anomalymodel.h5'

    if not os.path.exists(model_path):
        raise FileNotFoundError(f"Primary model file not found: {model_path}")
    with open(model_path, 'rb') as f:
        model = pickle.load(f)
    print(f"Loaded primary model ({model_path}) successfully.")

    # Load SECONDARY model (Anomaly-based)
    if TENSORFLOW_AVAILABLE:
        if os.path.exists(anomaly_model_path):
            try:
                anomaly_model = tf.keras.models.load_model(anomaly_model_path)
                print(f"Loaded anomaly model ({anomaly_model_path}) successfully.")
            except Exception as e:
                print(f"Error loading anomaly model '{anomaly_model_path}': {e}")
                traceback.print_exc()
                anomaly_model = None # Ensure it's None if loading fails
        else:
            print(f"Anomaly model file not found ({anomaly_model_path}), skipping load.")
            anomaly_model = None
    else:
        print("Skipping anomaly model loading because TensorFlow is not available.")


    # --- Load features, quantiles, dummies ---
    if not os.path.exists(features_path):
         raise FileNotFoundError(f"Top features file not found: {features_path}")
    with open(features_path, 'rb') as f:
        top_features = pickle.load(f)
    print(f"Loaded top features ({len(top_features)}).")

    print("Loading training data for preprocessing info...")
    if not os.path.exists(train_data_path):
         raise FileNotFoundError(f"Training data file not found: {train_data_path}")
    train_df_orig = pd.read_csv(
        train_data_path, sep=',', header=None, names=notebook_assigned_columns
    )
    print(f"Loaded {len(train_df_orig)} rows from {train_data_path}")

    # Coerce numeric and handle errors
    for col in numeric_var_names_from_notebook:
        if col in train_df_orig.columns:
            train_df_orig[col] = pd.to_numeric(train_df_orig[col], errors='coerce')
    rows_before = len(train_df_orig)
    train_df_orig.dropna(subset=numeric_var_names_from_notebook, inplace=True)
    rows_after = len(train_df_orig)
    if rows_before > rows_after: print(f"Warning: Dropped {rows_before - rows_after} rows during loading due to non-numeric values.")
    if rows_after == 0: raise ValueError("All rows dropped after numeric conversion. Check Train.txt format.")

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
    print(f"ERROR: Required file not found: {e}. Ensure model files and training data are in the correct paths.")
    # Set critical components to None to indicate failure
    model = anomaly_model = quantiles = dummy_columns_from_train = top_features = None
except Exception as e:
    print(f"An unexpected error occurred during model/data loading: {e}")
    traceback.print_exc()
    model = anomaly_model = quantiles = dummy_columns_from_train = top_features = None

# --- Preprocessing Functions ---
def outlier_capping(x, lower_quantile, upper_quantile):
    """Applies outlier capping based on pre-calculated quantiles."""
    if pd.isna(lower_quantile) or pd.isna(upper_quantile):
        # If quantiles couldn't be calculated (e.g., constant column), don't cap
        return x
    # Ensure input is numeric before clipping
    x_numeric = pd.to_numeric(x, errors='coerce')
    if pd.isna(x_numeric):
        return x # Return original if not numeric (error handled later)
    return np.clip(x_numeric, lower_quantile, upper_quantile)


def preprocess_input(input_data):
    """
    Applies the full preprocessing pipeline to user input (provided as a dict).
    Args:
        input_data (dict): Dictionary containing raw feature values.
                           Keys should match 'original_form_columns' (42 features).
    Returns:
        pd.DataFrame: Processed data ready for prediction (with top_features columns).
    Raises:
        ValueError: If preprocessing fails (e.g., missing columns, non-numeric data).
    """
    if not quantiles or not dummy_columns_from_train or not top_features:
         raise ValueError("Preprocessing information not loaded correctly.")

    try:
        # Create DataFrame from the single row dictionary
        input_df = pd.DataFrame([input_data])

        # Ensure all expected columns are present (even if they were missing in the dict, add as NaN perhaps? No, let's expect them.)
        # Reorder and select the 42 columns expected
        try:
            input_df = input_df[original_form_columns]
        except KeyError as e:
            missing_cols = set(original_form_columns) - set(input_df.columns)
            # This error should theoretically be caught earlier when creating the dict
            raise ValueError(f"Input data dictionary is missing expected feature columns for model: {missing_cols}") from e

        # Separate numeric and categorical based on the *model's* perspective (42 cols)
        input_num_df = input_df[numeric_var_names_from_notebook].copy()
        input_cat_df = input_df[cat_var_names_for_ui_dummies].copy()

        # Convert numeric columns, checking for errors *after* conversion attempt
        numeric_conversion_errors = {}
        for col in numeric_var_names_from_notebook:
            if col in input_num_df.columns:
                 # Store original type before conversion
                 # orig_val = input_num_df[col].iloc[0] # For single row DataFrame
                 input_num_df[col] = pd.to_numeric(input_num_df[col], errors='coerce')
                 # Check if NaN was introduced by coercion
                 if input_num_df[col].isnull().any():
                     # Find the original value that caused the error (might need original dict)
                     original_value = input_data.get(col, 'MISSING')
                     numeric_conversion_errors[col] = original_value
            else:
                 # This shouldn't happen if original_form_columns logic is correct
                 raise ValueError(f"Programming Error: Expected numeric column '{col}' not found in input_num DataFrame.")

        if numeric_conversion_errors:
            error_details = ", ".join([f"'{col}' (value: {val})" for col, val in numeric_conversion_errors.items()])
            raise ValueError(f"Invalid non-numeric value(s) found: {error_details}")


        # Apply outlier capping using the dedicated function
        for col in numeric_var_names_from_notebook:
            if col in quantiles and col in input_num_df.columns:
                 # Apply capping row-wise (though for single row, it's straightforward)
                 input_num_df[col] = input_num_df[col].apply(lambda x: outlier_capping(x, quantiles[col]['lower'], quantiles[col]['upper']))

        # Apply one-hot encoding for categorical
        input_dummies = pd.get_dummies(input_cat_df, columns=cat_var_names_for_ui_dummies, prefix=cat_var_names_for_ui_dummies, drop_first=True)
        # Align columns with those seen during training
        input_dummies_aligned = input_dummies.reindex(columns=dummy_columns_from_train, fill_value=0)

        # Combine processed numeric and categorical features
        processed_df = pd.concat([input_num_df, input_dummies_aligned], axis=1)

        # --- Final selection of top features ---
        # Ensure all required features are present before selecting
        missing_model_features = set(top_features) - set(processed_df.columns)
        if missing_model_features:
            # This indicates a mismatch between `top_features.pkl` and the preprocessing steps
            raise ValueError(f"Internal Error: Processed data is missing required model features: {missing_model_features}. Check preprocessing logic and 'top_features.pkl'.")

        final_input_df = processed_df[top_features]
        return final_input_df

    except KeyError as e:
        raise ValueError(f"Missing expected column during preprocessing step: {e}")
    except ValueError as e: # Catch specific ValueErrors from numeric conversion or capping
        raise # Re-raise specific ValueErrors
    except Exception as e:
        print(f"Unexpected error during input preprocessing: {e}") # Log details
        traceback.print_exc()
        raise ValueError(f"An unexpected error occurred during input preprocessing.") # Generic message


# --- Helper Function to Simulate Features from Packet (unchanged) ---
def _simulate_features_from_packet(packet):
    """ SIMULATION ONLY: Creates a dictionary with 42 features. """
    features = {col: 0 for col in original_form_columns} # Initialize with 42 keys
    proto, service, flag = 'unknown', 'other', 'SF'
    pkt_len = len(packet)

    if packet.haslayer(IP):
        ip_layer = packet.getlayer(IP)
        features['src_bytes'] = ip_layer.len
        features['dst_bytes'] = 0 # Crude approximation

        if packet.haslayer(TCP):
            proto = 'tcp'
            tcp_layer = packet.getlayer(TCP)
            dport, sport = tcp_layer.dport, tcp_layer.sport
            # Basic service mapping
            if dport == 80 or sport == 80: service = 'http'
            elif dport == 443 or sport == 443: service = 'http' # Treat as http for KDD
            elif dport == 21 or sport == 21: service = 'ftp'
            elif dport == 22 or sport == 22: service = 'ssh'
            elif dport == 23 or sport == 23: service = 'telnet'
            elif dport == 25 or sport == 25: service = 'smtp'
            elif dport == 53 or sport == 53: service = 'domain_u'
            else: service = 'private' # Default for unmapped TCP ports
            # Simplistic flag mapping
            if tcp_layer.flags.S: flag = 'S0' # SYN only
            elif tcp_layer.flags.R: flag = 'REJ' # RST
            elif tcp_layer.flags.F: flag = 'SF' # FIN (treat as established/finished)
            # Default guess for logged_in
            features['logged_in'] = 1 if service not in ['http', 'other', 'domain_u'] else 0

        elif packet.haslayer(UDP):
            proto = 'udp'
            udp_layer = packet.getlayer(UDP)
            dport, sport = udp_layer.dport, udp_layer.sport
            if dport == 53 or sport == 53: service = 'domain_u'
            elif dport == 67 or dport == 68: service = 'other' # DHCP
            elif dport == 161 or sport == 161: service = 'private' # SNMP
            else: service = 'private' # Default for unmapped UDP ports
            flag = 'SF' # UDP usually considered 'SF' in KDD context if no ICMP error

        elif packet.haslayer(ICMP):
            proto = 'icmp'
            icmp_layer = packet.getlayer(ICMP)
            # Map ICMP types to common KDD service names
            if icmp_layer.type == 8: service = 'ecr_i' # Echo request
            elif icmp_layer.type == 0: service = 'eco_i' # Echo reply
            elif icmp_layer.type == 3: service = 'urh_i' # Destination unreachable (example)
            else: service = 'oth_i' # Other ICMP
            flag = 'SF' # Generally 'SF' for ICMP unless specific error type implies others

    features['protocol_type'] = proto
    features['service'] = service
    features['flag'] = flag
    # Fill some common defaults reasonably
    features['duration'] = 0
    features['land'] = 1 if packet.haslayer(IP) and ip_layer.src == ip_layer.dst else 0
    features['count'] = 1
    features['srv_count'] = 1
    features['dst_host_count'] = 1 # Simplified state
    features['dst_host_srv_count'] = 1 # Simplified state
    features['same_srv_rate'] = 1.00 # Assuming single packet context
    features['dst_host_same_srv_rate'] = 1.00 # Assuming single packet context
    features['last_flag'] = 21 # A very common 'last_flag' value in KDD

    # Ensure all 42 features are present and converted to string for preprocess_input
    final_features = {col: str(features.get(col, 0)) for col in original_form_columns}
    return final_features


# --- Helper Function for Prediction from Packet Data (using simulation) ---
def _perform_packet_prediction(feature_dict):
    """
    Takes a dictionary of SIMULATED features, preprocesses, predicts with
    primary model, and conditionally predicts with anomaly model.
    Returns: tuple: (primary_prediction_str, anomaly_prediction_str_or_none)
    """
    if not model:
        raise ValueError("Primary model not loaded.")

    primary_prediction_result = "Error"
    anomaly_prediction_result = None

    try:
        # 1. Preprocess ONCE
        processed_input = preprocess_input(feature_dict) # Can raise ValueError

        # 2. Predict with Primary Model (Signature-based)
        prediction_primary = model.predict(processed_input)
        predicted_class_index = int(prediction_primary[0])
        primary_prediction_result = attack_mapping.get(predicted_class_index, f"Unknown ({predicted_class_index})")

        # 3. Conditionally Predict with Anomaly Model if Primary is 'Normal'
        if primary_prediction_result == 'Normal':
            if not anomaly_model:
                # print("Anomaly model not loaded, skipping anomaly check.") # Less verbose
                anomaly_prediction_result = "N/A (Model Unloaded)"
            elif not TENSORFLOW_AVAILABLE:
                 anomaly_prediction_result = "N/A (TF Missing)"
            else:
                try:
                    # Predict using the SAME preprocessed input
                    prediction_anomaly_raw = anomaly_model.predict(processed_input)
                    # --- MAP ANOMALY MODEL OUTPUT --- (Example: Class index 0=Normal, 1=Anomaly)
                    # Adjust this based on your anomaly model's output shape and meaning
                    if prediction_anomaly_raw.shape[1] > 1: # Softmax output
                         anomaly_class = np.argmax(prediction_anomaly_raw, axis=1)[0]
                    else: # Sigmoid output (assume threshold 0.5)
                         anomaly_class = (prediction_anomaly_raw[0][0] > 0.5).astype(int)

                    if anomaly_class == 1: # Assuming 1 means anomaly
                        anomaly_prediction_result = "Anomalous"
                    else:
                        anomaly_prediction_result = "Normal (Anomaly Model)"
                    # --------------------------------
                except Exception as anomaly_e:
                    print(f"Error during anomaly model prediction: {anomaly_e}")
                    traceback.print_exc()
                    anomaly_prediction_result = "Error (Anomaly Check Failed)"

        return primary_prediction_result, anomaly_prediction_result

    except ValueError as e: # Catch preprocessing errors
        print(f"ValueError during preprocessing for packet prediction: {e}")
        # Return error state instead of crashing the callback thread
        return "Error (Preprocessing)", None
    except Exception as e:
        print(f"Unexpected error during packet prediction: {e}")
        traceback.print_exc()
        return "Error (Prediction)", None


# --- Packet Processing Callback for Scapy ---
def process_packet(packet):
    """Callback function for scapy's sniff(). Simulates features, predicts, and emits results."""
    if not active_capture_sids: # Optimization: Stop if no clients are listening
        return

    client_sid = next(iter(active_capture_sids), None) # Get one client SID (simplistic)
    if not client_sid:
        return

    try:
        # 1. Simulate Features
        simulated_features = _simulate_features_from_packet(packet)

        # 2. Perform Prediction (gets both results now)
        prediction_primary, prediction_anomaly = _perform_packet_prediction(simulated_features)
        # print(f"Packet Prediction: Primary='{prediction_primary}', Anomaly='{prediction_anomaly}'") # Can be verbose

        # 3. Emit Combined Result via WebSocket
        packet_info = packet.summary() if hasattr(packet, 'summary') else "Packet Summary Unavailable"
        socketio.emit('capture_result', {
            'prediction': prediction_primary,       # Result from model 1
            'anomaly_prediction': prediction_anomaly, # Result from model 2 (or None/NA/Error)
            'packet_summary': packet_info,
            'timestamp': time.time()
        }, room=client_sid) # Send only to the specific client SID

    except Exception as e: # Catch-all for unexpected errors in the callback
        print(f"Unexpected error processing packet: {e}")
        traceback.print_exc()
        try:
            socketio.emit('capture_error', {'error': 'An unexpected error occurred during packet processing.'}, room=client_sid)
        except Exception as socket_err:
            print(f"Error sending error message via socket: {socket_err}")


# --- Background Sniffing Task ---
def sniffing_task(interface_name, sid):
    """Runs scapy.sniff in a loop until stop_event is set."""
    global stop_event
    print(f"Starting sniffing thread for SID: {sid} on interface: {interface_name or 'default'}")
    error_to_emit = None
    try:
        # Check privileges early
        if os.name == 'posix' and os.geteuid() != 0:
             error_to_emit = "Packet sniffing requires root privileges. Run the script with sudo."
             raise PermissionError(error_to_emit)

        if not SCAPY_AVAILABLE:
            error_to_emit = "Scapy is not available or failed to import. Cannot start sniffing."
            raise ImportError(error_to_emit)

        # Start sniffing
        # stop_filter is crucial for clean shutdown
        sniff(iface=interface_name, prn=process_packet, store=0, stop_filter=lambda p: stop_event.is_set())

    except PermissionError as e:
        print(f"PermissionError in sniffing_task: {e}")
        error_to_emit = str(e)
    except ImportError as e:
        print(f"ImportError in sniffing_task: {e}")
        error_to_emit = str(e)
    except OSError as e: # Catch Scapy/libpcap/interface errors
        print(f"OSError during sniff initiation or runtime: {e}")
        error_to_emit = f"Network interface error: {e}. Is '{interface_name}' correct, available, and do you have permissions?"
    except Exception as e:
        print(f"Unexpected error in sniffing_task: {e}")
        traceback.print_exc()
        error_to_emit = 'An unexpected error occurred during packet sniffing.'
    finally:
        print(f"Sniffing thread stopped for SID: {sid}.")
        # Emit error if one occurred during setup or runtime
        if error_to_emit:
             with app.app_context(): # Need app context to emit outside request
                 socketio.emit('capture_error', {'error': error_to_emit}, room=sid)
        # Clean up SID regardless of success/failure
        if sid in active_capture_sids:
            active_capture_sids.remove(sid)
        # If this was the last client, ensure stop_event is set (might be redundant but safe)
        if not active_capture_sids:
             stop_event.set()


# --- SocketIO Event Handlers ---
@socketio.on('connect')
def handle_connect():
    sid = request.sid
    print(f"Client connected: {sid}")
    # Check server readiness on connect
    error_msg = None
    if model is None or quantiles is None or dummy_columns_from_train is None or top_features is None:
        error_msg = 'Server Error: Primary model or essential preprocessing data not loaded. File/Real-time analysis may fail.'
    elif anomaly_model is None and TENSORFLOW_AVAILABLE:
         error_msg = 'Server Warning: Anomaly detection model failed to load. Real-time anomaly checks disabled.'
    elif not TENSORFLOW_AVAILABLE:
         error_msg = 'Server Info: TensorFlow not found. Anomaly detection disabled.'

    if error_msg:
        print(f"Notifying client {sid} about server status: {error_msg}")
        emit('server_error', {'error': error_msg}) # Send error/warning to connecting client

@socketio.on('disconnect')
def handle_disconnect():
    sid = request.sid
    print(f"Client disconnected: {sid}")
    global capture_thread, stop_event
    # Remove disconnected client from active list
    if sid in active_capture_sids:
        active_capture_sids.remove(sid)
        print(f"Removed SID {sid} from active capture list.")
    # If no clients are left capturing, signal the thread to stop
    if not active_capture_sids and capture_thread and capture_thread.is_alive():
        if not stop_event.is_set():
            print("Last client disconnected, signaling capture thread to stop.")
            stop_event.set()
        # Don't join the thread here to avoid blocking disconnect

@socketio.on('start_capture')
def handle_start_capture(data):
    sid = request.sid
    global capture_thread, stop_event, active_capture_sids

    # Check model readiness
    if model is None:
        emit('capture_error', {'error': 'Primary model not loaded, cannot start capture.'})
        return
    if not SCAPY_AVAILABLE:
         emit('capture_error', {'error': 'Scapy library not available on server. Cannot start capture.'})
         return
    # Warn if anomaly model isn't ready, but allow starting
    if anomaly_model is None:
         print(f"Warning for SID {sid}: Anomaly model not loaded. Capture starting without anomaly checks.")
         emit('capture_info', {'message': 'Warning: Anomaly model not loaded, anomaly checks disabled.'})

    # Simplified: Assume one global capture thread. If already running, just add SID.
    if capture_thread and capture_thread.is_alive():
        if sid not in active_capture_sids:
            active_capture_sids.add(sid)
            print(f"Capture already running. Added SID {sid} to active list.")
            emit('capture_started', {'message': 'Joined ongoing capture session.'})
        else:
            print(f"SID {sid} requested start, but is already in active list.")
            emit('capture_started', {'message': 'Capture is already running for you.'}) # Re-confirm
        return

    # --- Start a new capture thread ---
    interface = data.get('interface') if isinstance(data, dict) else None
    print(f"Received start_capture request from {sid} for interface: {interface or 'default'}")

    # Add SID *before* starting thread to avoid race condition in callback
    active_capture_sids.add(sid)
    stop_event.clear() # IMPORTANT: Reset stop event for the new session
    # Start the sniffing task in a background thread
    capture_thread = threading.Thread(target=sniffing_task, args=(interface, sid), daemon=True)
    capture_thread.start()
    emit('capture_started', {'message': f'Real-time capture started on interface: {interface or "default"}.'})
    print(f"Capture thread started for SID: {sid}")


@socketio.on('stop_capture')
def handle_stop_capture():
    sid = request.sid
    global capture_thread, stop_event, active_capture_sids
    print(f"Received stop_capture request from {sid}")

    # Remove this specific client from wanting capture
    if sid in active_capture_sids:
        active_capture_sids.remove(sid)
        print(f"Removed SID {sid} from active capture list on stop request.")

    # If no clients are left actively listening, signal the global thread to stop
    if not active_capture_sids and capture_thread and capture_thread.is_alive():
        if not stop_event.is_set():
            stop_event.set() # Signal the thread to stop sniffing
            print("Stop event set for capture thread (last client stopped listening).")
            # Wait briefly for thread to potentially stop (optional, improves perceived responsiveness)
            # capture_thread.join(timeout=1.0) # Add timeout to prevent hanging
            emit('capture_stopped', {'message': 'Capture stopped as you were the last listener.'})
        else:
            # Thread is already stopping
            emit('capture_stopped', {'message': 'Capture is already stopping.'})
    elif not (capture_thread and capture_thread.is_alive()):
        print("Stop request received, but no active capture thread found.")
        emit('capture_stopped', {'message': 'No capture was active.'})
        # Clean up state just in case
        active_capture_sids.clear()
        capture_thread = None
        stop_event.clear()
    else:
        # Other clients are still active, just acknowledge this client stopped listening
        print(f"Client {sid} stopped listening, but other clients remain: {active_capture_sids}")
        emit('capture_stopped', {'message': f'You stopped receiving data. Capture continues for other clients.'})


# --- Flask HTTP Routes ---

# Basic route to check if the server is up (optional)
@app.route('/', methods=['GET'])
def health_check():
    """ Basic health check / info endpoint. """
    status = {
        "status": "ok",
        "primary_model_loaded": model is not None,
        "preprocessing_ready": all(x is not None for x in [quantiles, dummy_columns_from_train, top_features]),
        "tensorflow_available": TENSORFLOW_AVAILABLE,
        "anomaly_model_loaded": anomaly_model is not None,
        "scapy_available": SCAPY_AVAILABLE
    }
    return jsonify(status)

# Serve a simple HTML page if needed for testing SocketIO directly (optional)
@app.route('/test', methods=['GET'])
def index_page():
    """Serves a simple HTML page for testing (optional)."""
    # You would need a 'templates/index.html' file for this
    return render_template('index.html', error=None)


def preprocess_dataframe(input_df_full):
    """
    Applies the full preprocessing pipeline to an entire DataFrame.
    Args:
        input_df_full (pd.DataFrame): DataFrame containing raw feature values.
                                      MUST have the 43 columns defined in notebook_assigned_columns.
    Returns:
        pd.DataFrame: Processed data ready for batch prediction (with top_features columns).
    Raises:
        ValueError: If preprocessing fails (e.g., missing columns, non-numeric data).
    """
    # --- Ensure global variables needed are accessible here ---
    # (quantiles, dummy_columns_from_train, top_features,
    #  original_form_columns, numeric_var_names_from_notebook,
    #  cat_var_names_for_ui_dummies)
    # ---------------------------------------------------------
    if not quantiles or not dummy_columns_from_train or not top_features:
         raise ValueError("Preprocessing information (quantiles/dummies/features) not loaded correctly.")
    if not original_form_columns or not numeric_var_names_from_notebook or not cat_var_names_for_ui_dummies:
         raise ValueError("Preprocessing configuration column lists are missing.")


    print(f"Starting batch preprocessing for {len(input_df_full)} rows...") # Log start

    try:
        # --- Step 1: Select the 42 columns needed for the model ---
        # Work on a copy to avoid modifying the original DataFrame passed in
        try:
            input_df = input_df_full[original_form_columns].copy()
        except KeyError as e:
            missing_req_cols = set(original_form_columns) - set(input_df_full.columns)
            raise ValueError(f"Input DataFrame is missing required columns for the model: {missing_req_cols}") from e

        # --- Step 2: Separate numeric and categorical columns ---
        # Ensure the lists used here only contain columns present in 'original_form_columns'
        relevant_numeric_vars = [col for col in numeric_var_names_from_notebook if col in input_df.columns]
        relevant_cat_vars = [col for col in cat_var_names_for_ui_dummies if col in input_df.columns]

        input_num_df = input_df[relevant_numeric_vars].copy()
        input_cat_df = input_df[relevant_cat_vars].copy()

        # --- Step 3: Convert numeric columns and check for errors ---
        numeric_conversion_errors = {}
        print(f"Converting {len(relevant_numeric_vars)} numeric columns...")
        for col in relevant_numeric_vars:
             # Store original non-numeric values before converting
             original_non_numeric = input_num_df[pd.to_numeric(input_num_df[col], errors='coerce').isna() & input_num_df[col].notna()]
             if not original_non_numeric.empty:
                  numeric_conversion_errors[col] = original_non_numeric[col].unique()[:5].tolist() # Store examples

             input_num_df[col] = pd.to_numeric(input_num_df[col], errors='coerce')

        # Check if any NaNs exist *after* coercion across all numeric columns
        if input_num_df.isnull().values.any():
             failed_cols_details = []
             for col in relevant_numeric_vars:
                 if input_num_df[col].isnull().any():
                      original_vals = numeric_conversion_errors.get(col, "Unknown original values")
                      failed_cols_details.append(f"'{col}' (examples causing error: {original_vals})")
             # Raise a single, informative error
             raise ValueError(f"Invalid non-numeric value(s) found in columns: {'; '.join(failed_cols_details)}. Cannot proceed.")


        # --- Step 4: Apply outlier capping (vectorized) ---
        print("Applying outlier capping...")
        for col in relevant_numeric_vars:
            # Check if quantiles exist for this column (they might not if column was constant)
            if col in quantiles:
                 lower_q = quantiles[col].get('lower') # Use .get for safety
                 upper_q = quantiles[col].get('upper')
                 # Only clip if both quantiles are valid numbers
                 if pd.notna(lower_q) and pd.notna(upper_q):
                     input_num_df[col] = input_num_df[col].clip(lower=lower_q, upper=upper_q)
                 # else:
                 #     print(f"Skipping capping for '{col}' due to missing/invalid quantiles.")
        print("Outlier capping applied.")


        # --- Step 5: Apply one-hot encoding for categorical ---
        print(f"Applying one-hot encoding for {len(relevant_cat_vars)} categorical columns...")
        if not relevant_cat_vars:
             print("No categorical columns found to encode.")
             # Create an empty DataFrame with the expected dummy columns if none are present
             # This might happen if the input only had numeric features matching the categorical list
             input_dummies_aligned = pd.DataFrame(columns=dummy_columns_from_train, index=input_df.index).fillna(0)
        else:
             input_dummies = pd.get_dummies(input_cat_df, columns=relevant_cat_vars, prefix=relevant_cat_vars, drop_first=True)
             # Align columns with those seen during training, filling missing ones with 0
             input_dummies_aligned = input_dummies.reindex(columns=dummy_columns_from_train, fill_value=0)
        print(f"One-hot encoding done. Resulting dummy features shape: {input_dummies_aligned.shape}")

        # --- Step 6: Combine processed numeric and categorical features ---
        # Ensure indices align if input_num_df or input_dummies_aligned were modified
        processed_df = pd.concat([input_num_df.reset_index(drop=True),
                                  input_dummies_aligned.reset_index(drop=True)], axis=1)
        print("Combined numeric and dummy features.")

        # --- Step 7: Final selection of top features ---
        # Check if all features expected by the model are present in the processed DataFrame
        missing_model_features = set(top_features) - set(processed_df.columns)
        if missing_model_features:
            # This is a critical error indicating a mismatch in the preprocessing pipeline or loaded features
            raise ValueError(f"Internal Error: Processed data is missing required model features: {missing_model_features}. Check definition of 'top_features' and preprocessing steps.")

        # Select only the top features required by the model
        final_input_df = processed_df[top_features]
        print(f"Preprocessing complete. Final shape for model: {final_input_df.shape}")
        return final_input_df

    except KeyError as e:
        # Catch errors related to missing columns during selection/processing
        raise ValueError(f"Missing expected column during batch preprocessing step: {e}") from e
    except ValueError as e: # Catch specific ValueErrors (e.g., non-numeric)
        # Log the specific error before re-raising
        print(f"ValueError during batch preprocessing: {e}")
        raise # Re-raise specific ValueErrors
    except Exception as e:
        # Catch any other unexpected errors during the process
        print(f"Unexpected error during batch preprocessing: {e}")
        traceback.print_exc()
        # Raise a generic error to signal failure
        raise ValueError("An unexpected error occurred during batch preprocessing.")


# --- API Endpoint for File Upload (Handles Full CSV) ---
@app.route('/api/analyze', methods=['POST'])
def analyze_api():
    """
    API endpoint to analyze CSV file content sent as JSON.
    Processes the data using vectorized operations after cleaning.
    Expects JSON: {"csv_data": "full_csv_content_as_string"}
    CSV Requirements: NO header row, exactly 43 columns per row.
    """
    print("\n--- Full CSV File Analysis Request Received ---")

    # --- Initial Server Readiness and Request Checks ---
    if not model or not quantiles or not dummy_columns_from_train or not top_features:
        print("API Error: Server not ready (model or preprocessing info missing).")
        return jsonify({"error": "Server configuration error: Model or preprocessing data missing. Cannot analyze."}), 500

    if not request.is_json:
        print("API Error: Request Content-Type was not application/json.")
        return jsonify({"error": "Request must be JSON."}), 415

    data = request.get_json()
    if not data or 'csv_data' not in data:
        print("API Error: Missing 'csv_data' in JSON payload.")
        return jsonify({"error": "Missing 'csv_data' field in JSON payload."}), 400

    csv_data_string = data['csv_data']
    if not isinstance(csv_data_string, str) or not csv_data_string.strip():
         print("API Error: Received empty or non-string 'csv_data'.")
         return jsonify({"error": "'csv_data' must be a non-empty string."}), 400

    print(f"API Received CSV data string (length: {len(csv_data_string)})")

    # --- Step 1: Clean the input string ---
    # a) Strip leading/trailing whitespace first
    cleaned_string = csv_data_string.strip()
    original_length = len(cleaned_string) # Length after initial strip

    # b) Strip potential quotes around the whole block (common if file has outer quotes)
    if cleaned_string.startswith('"') and cleaned_string.endswith('"'):
        cleaned_string = cleaned_string[1:-1]
        print(f"Stripped leading/trailing quotes from block. Original length: {original_length}, New length: {len(cleaned_string)}")

    # c) Replace problematic quote-newline-quote patterns specifically
    count_before = cleaned_string.count('"\n"')
    if count_before > 0:
        cleaned_string = cleaned_string.replace('"\n"', '\n')
        print(f"Replaced {count_before} instances of '\"\\n\"' pattern with '\\n'.")

    # d) Check if cleaning resulted in an empty string
    if not cleaned_string.strip():
        print("API Warning: CSV data became empty after cleaning steps.")
        # Return success with empty results, or potentially a 400 error
        return jsonify({"summary": {}, "total_rows": 0, "processed_rows": 0, "error_rows": 0, "error": "CSV data empty after cleaning."}), 200

    # --- Step 2: Parse CSV into DataFrame ---
    total_rows = 0
    processed_rows = 0
    df = None # Initialize df
    try:
        # Use the CLEANED string
        csv_file = io.StringIO(cleaned_string)

        # --- Debug Print: Show tail end of data going into pandas ---
        print("-" * 20)
        print("DEBUG: Data tail passed to read_csv (after cleaning):")
        # Show last 200 chars, or fewer if string is short
        print(cleaned_string[max(-200, -len(cleaned_string)):])
        print("-" * 20)
        # -------------------------------------------------------------

        try:
             # Parse the cleaned data
             df = pd.read_csv(
                 csv_file,
                 header=None, # Crucial: No header row expected
                 names=notebook_assigned_columns, # Assign the 43 column names
                 low_memory=False,
                 quotechar='"', # Standard quoting character
                 skipinitialspace=True, # Handle potential spaces after commas
                 on_bad_lines='warn' # Warn about lines not matching columns, but try to parse
                 # engine='python' # Try if C engine still fails unexpectedly after cleaning
             )
             total_rows = len(df)
             print(f"Successfully parsed CSV into DataFrame with {total_rows} rows and {len(df.columns)} columns.")

             # Validate column count (essential check)
             if len(df.columns) != num_expected_file_columns:
                 raise ValueError(f"Incorrect number of columns parsed. Expected {num_expected_file_columns}, but DataFrame has {len(df.columns)}. Check CSV format.")

             # Handle case where file is parsed but yields no rows (e.g., all lines skipped)
             if total_rows == 0:
                  print("Parsed CSV resulted in an empty DataFrame (potentially all rows skipped or file was empty).")
                  return jsonify({"summary": {}, "total_rows": 0, "processed_rows": 0, "error_rows": 0}), 200

        except pd.errors.ParserError as e:
             # Error during parsing (e.g., tokenizer errors like EOF)
             print(f"API Error: Failed to parse CSV data AFTER CLEANING. Error: {e}")
             # Provide context back to the user
             error_message = f"CSV Parsing Error after cleaning: {e}. Ensure each row has exactly {num_expected_file_columns} comma-separated values and check quoting."
             return jsonify({"error": error_message}), 400
        except ValueError as e: # Catch column count validation error
             print(f"API Error: {e}")
             return jsonify({"error": str(e)}), 400
        except Exception as e: # Catch other unexpected read_csv errors
            print(f"API Error: Unexpected error reading cleaned CSV data. Error: {e}")
            traceback.print_exc()
            return jsonify({"error": "An unexpected error occurred while reading the cleaned CSV data."}), 500

        # --- Step 3: Preprocess the *entire* DataFrame ---
        processed_df = None # Initialize
        try:
            # Pass a copy to avoid modifying original df if it's large or reused
            processed_df = preprocess_dataframe(df.copy())
            processed_rows = len(processed_df)
            print(f"Batch preprocessing successful for {processed_rows} rows.")
        except ValueError as e:
            # Catch specific errors raised by preprocess_dataframe (e.g., non-numeric data)
            print(f"API Error: Batch preprocessing failed: {e}")
            return jsonify({
                "error": f"Preprocessing failed: {e}. Check data types in the CSV.",
                "total_rows": total_rows,
                "processed_rows": 0,
                "error_rows": total_rows # All rows failed preprocessing
            }), 400 # Bad Request due to bad data for preprocessing
        except Exception as e:
             print(f"API Error: Unexpected error during batch preprocessing: {e}")
             traceback.print_exc()
             return jsonify({"error": "An internal server error occurred during data preprocessing."}), 500

        # --- Step 4: Predict on the *entire* batch ---
        print(f"Starting batch prediction for {processed_rows} rows...")
        all_predictions_indices = None # Initialize
        try:
            all_predictions_indices = model.predict(processed_df)
            print(f"Batch prediction completed. Received {len(all_predictions_indices)} predictions.")
            # Basic sanity check on prediction output length
            if len(all_predictions_indices) != processed_rows:
                print(f"Warning: Number of predictions ({len(all_predictions_indices)}) does not match number of processed rows ({processed_rows}).")
                # Decide how to handle this - maybe return an error or proceed cautiously
        except Exception as e:
             print(f"API Error: Model prediction failed for the batch: {e}")
             traceback.print_exc()
             return jsonify({"error": "An internal server error occurred during model prediction."}), 500

        # --- Step 5: Map predictions and Aggregate results ---
        print("Mapping predictions to names...")
        final_summary = {}
        try:
            # Use list comprehension for efficient mapping
            all_prediction_names = [attack_mapping.get(int(idx), f"Unknown ({idx})") for idx in all_predictions_indices]
            print("Aggregating results...")
            summary_counts = Counter(all_prediction_names)
            final_summary = dict(summary_counts) # Convert Counter to dict for JSON
        except (ValueError, TypeError, IndexError) as e:
             print(f"API Error: Failed to map prediction indices or aggregate results: {e}")
             traceback.print_exc()
             # Decide how to handle - return error or return partial results? Returning error is safer.
             return jsonify({"error": "An internal server error occurred while interpreting/aggregating model predictions."}), 500

        print(f"--- API Analysis Complete ---")
        print(f"Total Rows Read from Input: {total_rows}")
        print(f"Rows Successfully Processed & Predicted: {processed_rows}")
        # Errors here assumes batch processing succeeded, so individual errors weren't tracked this way
        print(f"Prediction Summary: {final_summary}")

        # --- Construct successful response JSON ---
        response_data = {
            "summary": final_summary,
            "total_rows": total_rows, # Rows read from the input string sent by client
            "processed_rows": processed_rows, # Rows that made it through preprocessing+prediction
            "error_rows": total_rows - processed_rows # Rows dropped by parsing (on_bad_lines='skip') or failing preprocessing
        }
        # If using on_bad_lines='warn', error_rows might be 0 even if warnings occurred.

        return jsonify(response_data), 200

    except Exception as e:
        # Catch-all for any unexpected errors in the main structure of the function
        print(f"API Exception: An unexpected error occurred in the main analysis block: {e}")
        traceback.print_exc()
        return jsonify({"error": "An internal server error occurred during analysis."}), 500

# --- Run the App with SocketIO ---
if __name__ == '__main__':
    print("Starting Flask-SocketIO server...")
    # --- Readiness Checks ---
    model_ready = True
    if model is None or quantiles is None or dummy_columns_from_train is None or top_features is None:
        print("CRITICAL WARNING: Primary model or critical preprocessing info failed to load. Check logs.")
        print("File/Real-time analysis features will be unavailable or may fail.")
        model_ready = False
    else:
        print("Primary model and preprocessing info loaded successfully.")
        print(f"-> File Upload API expects CSV data with {num_expected_file_columns} columns (NO HEADER).")
        print(f"-> Model preprocessing uses {len(top_features)} features after transformations.")

    if TENSORFLOW_AVAILABLE:
        if anomaly_model is None:
             print("WARNING: Anomaly detection model failed to load, but TensorFlow is installed.")
             print("Real-time analysis will proceed WITHOUT anomaly checks for 'Normal' packets.")
        else:
             print("Anomaly detection model loaded successfully.")
    else:
        print("INFO: TensorFlow not found. Anomaly detection model is disabled.")

    if not SCAPY_AVAILABLE:
         print("WARNING: Scapy not installed or failed to load. Real-time analysis feature disabled.")
    elif os.name == 'posix' and os.geteuid() != 0:
         print("WARNING: Script not run as root. Real-time packet sniffing will likely fail due to permissions.")
    elif SCAPY_AVAILABLE:
         print("Scapy is available. Real-time analysis enabled (requires root/admin privileges).")

    if not model_ready:
        print("\n*** SERVER STARTING WITH CRITICAL ERRORS - Functionality will be limited. ***\n")

    print(f"Server starting on http://0.0.0.0:5000")
    # Use allow_unsafe_werkzeug=True ONLY if needed for your Werkzeug/SocketIO version combo
    socketio.run(app, host='0.0.0.0', port=5000, debug=False, use_reloader=False, allow_unsafe_werkzeug=True)