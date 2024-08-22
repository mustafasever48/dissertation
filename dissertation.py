import pandas as pd
import joblib
import subprocess
import time

# Load the XGBoost model you trained and saved
model_path = 'xgb_model.pkl'
xgb_model = joblib.load(model_path)

# Files and fields to read
file_path = '/home/mustafa/output.csv'
columns = ['frame.len', 'frame.time_relative', 'tcp.seq', 'tcp.ack', 'tcp.window_size',
           'tcp.analysis.retransmission', 'tcp.analysis.out_of_order', 'tcp.analysis.duplicate_ack', 
           'tcp.analysis.ack_rtt', 'tcp.analysis.initial_rtt', 'ip.src_192.168.0.26', 
           'ip.src_34.245.116.120', 'ip.dst_192.168.0.26', 'ip.dst_34.245.116.120']

# Initialize counters
lost_packet_count = 0
last_warning_lost_packet_count = 0

def handle_packet(packet_info):
    global lost_packet_count, last_warning_lost_packet_count
    try:
        # Fill in missing columns
        df_packet = pd.DataFrame([packet_info], columns=columns).fillna(0)
        
        X_packet = df_packet[columns]  # select all required columns
        y_pred = xgb_model.predict(X_packet)

        if y_pred[0] == 1:
            lost_packet_count += 1
            print("Lost packet estimated.")
            
            # warning limit
            if lost_packet_count // 10 > last_warning_lost_packet_count:
                last_warning_lost_packet_count = lost_packet_count // 10
                print(f"Warning: {lost_packet_count} lost packets processed. High packet loss detected. Network check suggested!")
        
        else:
            print("No need to retransmit.")

    except Exception as e:
        print(f"Error occurred while processing the package: {e}")

def read_tshark_output(file_path):
    # A loop that reads the file from beginning to end and constantly checks for new packages
    last_position = 0
    while True:
        try:
            with open(file_path, 'r') as f:
                f.seek(last_position)
                new_data = f.readlines()
                
                if new_data:
                    for line in new_data:
                        packet_data = line.strip().split(',')
                        if len(packet_data) < len(columns):
                            print("Error occurred while processing package: Expected number of columns missing")
                            continue
                        try:
                            packet_info = {
                                'frame.len': int(packet_data[3].strip('"')) if packet_data[3] else 0,
                                'frame.time_relative': float(packet_data[4].strip('"')) if packet_data[4] else 0.0,
                                'tcp.seq': int(packet_data[5].strip('"')) if packet_data[5] else 0,
                                'tcp.ack': int(packet_data[6].strip('"')) if packet_data[6] else 0,
                                'tcp.window_size': int(packet_data[7].strip('"')) if packet_data[7] else 0,
                                'tcp.analysis.retransmission': int(packet_data[8].strip('"')) if packet_data[8] else 0,
                                'tcp.analysis.out_of_order': int(packet_data[10].strip('"')) if packet_data[10] else 0,
                                'tcp.analysis.duplicate_ack': int(packet_data[11].strip('"')) if packet_data[11] else 0,
                                'tcp.analysis.ack_rtt': float(packet_data[12].strip('"')) if packet_data[12] else 0.0,
                                'tcp.analysis.initial_rtt': float(packet_data[13].strip('"')) if packet_data[13] else 0.0,
                                'ip.src_192.168.0.26': 1 if packet_data[1].strip('"') == '192.168.0.26' else 0,
                                'ip.src_34.245.116.120': 1 if packet_data[1].strip('"') == '34.245.116.120' else 0,
                                'ip.dst_192.168.0.26': 1 if packet_data[2].strip('"') == '192.168.0.26' else 0,
                                'ip.dst_34.245.116.120': 1 if packet_data[2].strip('"') == '34.245.116.120' else 0
                            }
                            handle_packet(packet_info)
                        except (IndexError, ValueError) as e:
                            print(f"IndexError occurred while processing the package: {e}")
                        except Exception as e:
                            print(f"Error occurred while processing the package: {e}")
                
                last_position = f.tell()
                time.sleep(1)  # Wait (second) to recheck the file
        
        except FileNotFoundError:
            print(f"File not found: {file_path}")
            break
        except Exception as e:
            print(f"An error occurred while reading the file: {e}")
            time.sleep(5)  # If an error occurs, wait a while and try again.

if __name__ == "__main__":
    read_tshark_output(file_path)
