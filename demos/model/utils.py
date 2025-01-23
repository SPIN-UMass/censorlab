import subprocess
import numpy as np
from collections import defaultdict

def parse_pcap_to_arrays(pcap_file):
    """
    Parse a pcap file using tshark to aggregate packets into connections
    and output two Nx10 numpy arrays: one for TCP payload sizes and
    another for directions.

    Parameters:
        pcap_file (str): Path to the pcap file.

    Returns:
        tuple: (sizes_array, directions_array)
    """
    # Example usage
    # sizes, directions = parse_pcap_to_arrays("example.pcap")
    # print(sizes)
    # print(directions)
    # Use tshark to extract TCP packets with relevant details
    tshark_cmd = [
        "tshark",
        "-r", pcap_file,
        "-T", "fields",
        "-e", "tcp.stream",
        "-e", "ip.src",
        "-e", "ip.dst",
        "-e", "tcp.len",
        "-E", "separator=,"
    ]

    try:
        process = subprocess.Popen(tshark_cmd, stdout=subprocess.PIPE, text=True)
    except Exception as e:
        raise RuntimeError(f"Error running tshark: {e}")

    connections = defaultdict(list)

    # Process tshark output lazily
    for line in iter(process.stdout.readline, ""):
        fields = line.strip().split(",")
        if len(fields) < 4:
            print(f"Error unpacking line: {line.strip()}")
            continue

        stream_id, src_ip, dst_ip, *tcp_len_field = fields
        tcp_len = int(tcp_len_field[0]) if tcp_len_field and tcp_len_field[0].isdigit() else 0

        # Aggregate packets by stream ID
        connections[stream_id].append((src_ip, dst_ip, tcp_len))

    process.stdout.close()
    process.wait()

    # Initialize arrays for sizes and directions
    sizes = []
    directions = []

    for packets in connections.values():
        initiator = packets[0][0]  # Source IP of the first packet

        # Extract sizes and directions for the first 10 packets
        stream_sizes = []
        stream_directions = []

        for packet in packets[:10]:
            src_ip, _, tcp_len = packet
            stream_sizes.append(tcp_len)
            stream_directions.append(1 if src_ip == initiator else -1)

        # Pad with -1 to ensure length is 10
        while len(stream_sizes) < 10:
            stream_sizes.append(-1)
            stream_directions.append(-1)

        sizes.append(stream_sizes)
        directions.append(stream_directions)

    # Convert lists to NumPy arrays
    sizes_array = np.array(sizes, dtype=int)
    directions_array = np.array(directions, dtype=int)

    return sizes_array, directions_array
import numpy as np

def combine_data(x_web_len, x_web_dir, x_ssgo_len, x_ssgo_dir):
    """
    Combine web and SSGO data into a single array for PyTorch and return an indicator array.

    Parameters:
        x_web_len (numpy.ndarray): Array of shape (N, 10) containing TCP payload sizes for web data.
        x_web_dir (numpy.ndarray): Array of shape (N, 10) containing directions for web data.
        x_ssgo_len (numpy.ndarray): Array of shape (M, 10) containing TCP payload sizes for SSGO data.
        x_ssgo_dir (numpy.ndarray): Array of shape (M, 10) containing directions for SSGO data.

    Returns:
        tuple: 
            numpy.ndarray: Combined array of shape (N+M, 10, 2).
            numpy.ndarray: Indicator array of shape (N+M, 1) with 0 for web rows and 1 for SSGO rows.
    """
    # Example usage
    # x_web_len = np.random.randint(0, 100, (5, 10))
    # x_web_dir = np.random.choice([1, -1], (5, 10))
    # x_ssgo_len = np.random.randint(0, 100, (3, 10))
    # x_ssgo_dir = np.random.choice([1, -1], (3, 10))
    # result, labels = combine_data(x_web_len, x_web_dir, x_ssgo_len, x_ssgo_dir)
    # print(result.shape)  # Expected shape: (8, 10, 2)
    # print(labels.shape)  # Expected shape: (8, 1)
    # Ensure the inputs have the expected shapes
    assert x_web_len.shape == x_web_dir.shape, "Web length and direction arrays must have the same shape."
    assert x_ssgo_len.shape == x_ssgo_dir.shape, "SSGO length and direction arrays must have the same shape."
    assert x_web_len.shape[1] == 10, "Web arrays must have 10 columns."
    assert x_ssgo_len.shape[1] == 10, "SSGO arrays must have 10 columns."

    # Stack lengths and directions for web data along the last dimension
    web_data = np.stack((x_web_len, x_web_dir), axis=-1)

    # Stack lengths and directions for SSGO data along the last dimension
    ssgo_data = np.stack((x_ssgo_len, x_ssgo_dir), axis=-1)

    # Concatenate web and SSGO data along the first dimension
    combined_data = np.concatenate((web_data, ssgo_data), axis=0)

    # Create an indicator array with 0 for web rows and 1 for SSGO rows
    web_labels = np.zeros((x_web_len.shape[0], 1), dtype=int)
    ssgo_labels = np.ones((x_ssgo_len.shape[0], 1), dtype=int)
    labels = np.concatenate((web_labels, ssgo_labels), axis=0)

    return combined_data, labels
