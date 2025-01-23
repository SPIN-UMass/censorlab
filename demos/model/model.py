import torch
import torch.nn as nn
import torch.optim as optim
from torch.utils.data import DataLoader, TensorDataset
import onnx

# Define the neural network model
class FeedForwardNN(nn.Module):
    def __init__(self, input_size):
        super(FeedForwardNN, self).__init__()
        self.fc1 = nn.Linear(input_size, 64)
        self.relu = nn.ReLU()
        self.fc2 = nn.Linear(64, 32)
        self.fc3 = nn.Linear(32, 1)
        self.sigmoid = nn.Sigmoid()

    def forward(self, x):
        x = self.fc1(x)
        x = self.relu(x)
        x = self.fc2(x)
        x = self.relu(x)
        x = self.fc3(x)
        x = self.sigmoid(x)
        return x

# Train the model
def train_model(x, y, epochs=20, batch_size=32, learning_rate=0.001):
    """
    Train a feed-forward neural network using the given data.

    Parameters:
        x (numpy.ndarray): Input data of shape (N+M, 10, 2).
        y (numpy.ndarray): Labels of shape (N+M, 1).
        epochs (int): Number of training epochs.
        batch_size (int): Batch size for training.
        learning_rate (float): Learning rate for the optimizer.

    Returns:
        model (FeedForwardNN): Trained neural network model.
    """
    # Convert numpy arrays to PyTorch tensors
    x_tensor = torch.tensor(x, dtype=torch.float32)
    y_tensor = torch.tensor(y, dtype=torch.float32)

    # Flatten the input from (N+M, 10, 2) to (N+M, 20)
    x_tensor = x_tensor.view(x_tensor.shape[0], -1)

    # Create DataLoader for batching
    dataset = TensorDataset(x_tensor, y_tensor)
    dataloader = DataLoader(dataset, batch_size=batch_size, shuffle=True)

    # Initialize model, loss function, and optimizer
    model = FeedForwardNN(input_size=x_tensor.shape[1])
    criterion = nn.BCELoss()
    optimizer = optim.Adam(model.parameters(), lr=learning_rate)

    # Training loop
    for epoch in range(epochs):
        model.train()
        epoch_loss = 0.0

        for batch_x, batch_y in dataloader:
            # Forward pass
            outputs = model(batch_x).squeeze()
            loss = criterion(outputs, batch_y.squeeze())

            # Backward pass
            optimizer.zero_grad()
            loss.backward()
            optimizer.step()

            epoch_loss += loss.item()

        print(f"Epoch [{epoch + 1}/{epochs}], Loss: {epoch_loss / len(dataloader):.4f}")

    return model

# Export the model to ONNX format
def export_model_to_onnx(model, output_file="model.onnx"):
    """
    Export the trained model to ONNX format.

    Parameters:
        model (FeedForwardNN): Trained PyTorch model.
        output_file (str): Path to save the ONNX model.
    """
    model.eval()

    # Derive the input size from the model's first layer
    input_size = model.fc1.in_features

    # Create a dummy input with the correct shape
    dummy_input = torch.randn(1, input_size, dtype=torch.float32, requires_grad=False)

    # Export the model to ONNX
    torch.onnx.export(
        model,
        dummy_input,
        output_file,
        export_params=True,
        opset_version=11,
        do_constant_folding=True,
        input_names=["float_input"],
        output_names=["probabilities"],
        dynamic_axes={"float_input": {0: "batch_size"}, "probabilities": {0: "batch_size"}}
    )
    print(f"Model exported to {output_file}")

# Example usage
# Assuming x and y are the combined input and indicator arrays from the combine_data function
# x = np.random.rand(100, 10, 2)
# y = np.random.randint(0, 2, (100, 1))
# model = train_model(x, y)
# export_model_to_onnx(model)
