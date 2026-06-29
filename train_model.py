import torch
import torch.nn as nn
import torch.optim as optim
import numpy as np

# 1. Hyperparameters & Character Vocabulary Map
CHARS = "abcdefghijklmnopqrstuvwxyz0123456789-._~:/?#[]@!$&'()*+,;="
char_to_idx = {char: idx + 1 for idx, char in enumerate(CHARS)} # 0 reserved for padding
VOCAB_SIZE = len(char_to_idx) + 1
EMBEDDING_DIM = 32
HIDDEN_DIM = 64
MAX_LEN = 100

def url_to_tensor(url: str) -> torch.Tensor:
    """Converts a raw string URL into a standardized mathematical index vector."""
    url = url.lower()[:MAX_LEN]
    tensor = torch.zeros(MAX_LEN, dtype=torch.long)
    for i, char in enumerate(url):
        if char in char_to_idx:
            tensor[i] = char_to_idx[char]
    return tensor

# 2. Build the Lightweight Deep Learning Architecture
class URLClassifierLSTM(nn.Module):
    def __init__(self, vocab_size, embedding_dim, hidden_dim):
        super(URLClassifierLSTM, self).__init__()
        self.embedding = nn.Embedding(vocab_size, embedding_dim, padding_idx=0)
        self.lstm = nn.LSTM(embedding_dim, hidden_dim, batch_first=True)
        self.fc = nn.Linear(hidden_dim, 1)
        self.sigmoid = nn.Sigmoid()
        
    def forward(self, x):
        embedded = self.embedding(x)
        lstm_out, (ht, ct) = self.lstm(embedded)
        # Pull the final hidden state vector output from the sequence loop
        out = self.fc(ht[-1])
        return self.sigmoid(out)

# 3. Local Training Execution Simulator
if __name__ == "__main__":
    print("🧠 Initializing local deep learning dataset matrices...")
    
    # Simple training matrix sample vectors (Benign vs Malicious patterns)
    sample_urls = [
        "google.com", "github.com", "linkedin.com/feed", "amazon.in/orders",
        "secure-paypal-login-update.com", "verify-bank-account-signin.xyz",
        "netflix-free-premium-login.net", "http-192-168-1-login-routing.top"
    ]
    labels = torch.tensor([[0.0], [0.0], [0.0], [0.0], [1.0], [1.0], [1.0], [1.0]])
    
    # Parse inputs into a batch tensor
    input_tensors = torch.stack([url_to_tensor(url) for url in sample_urls])
    
    model = URLClassifierLSTM(VOCAB_SIZE, EMBEDDING_DIM, HIDDEN_DIM)
    criterion = nn.BCELoss()
    optimizer = optim.Adam(model.parameters(), lr=0.01)
    
    print("🏋️ Starting localized model backpropagation training loops...")
    for epoch in range(50): # 50 gradient iterations
        optimizer.zero_grad()
        predictions = model(input_tensors)
        loss = criterion(predictions, labels)
        loss.backward()
        optimizer.step()
        
        if (epoch + 1) % 10 == 0:
            print(f"   Epoch [{epoch+1}/50] -> Current Engine Loss Value: {loss.item():.4f}")
            
    # Save the native model brain architecture straight to your project disk
    torch.save(model.state_dict(), "phishguard_model.pth")
    print("💾 Success! Ultra-light model weights saved securely as 'phishguard_model.pth'.")