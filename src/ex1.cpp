#include <iostream>
#include <string>
#include <vector>
#include <sstream>
#include <iomanip>
#include <openssl/evp.h>

using namespace std;

string sha256(const string &data) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) throw runtime_error("Failed to create EVP_MD_CTX");

    if (EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr) != 1) {
        EVP_MD_CTX_free(ctx);
        throw runtime_error("EVP_DigestInit_ex failed");
    }

    if (EVP_DigestUpdate(ctx, data.c_str(), data.size()) != 1) {
        EVP_MD_CTX_free(ctx);
        throw runtime_error("EVP_DigestUpdate failed");
    }

    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int length = 0;
    if (EVP_DigestFinal_ex(ctx, hash, &length) != 1) {
        EVP_MD_CTX_free(ctx);
        throw runtime_error("EVP_DigestFinal_ex failed");
    }

    EVP_MD_CTX_free(ctx);

    std::ostringstream oss;
    for (unsigned int i = 0; i < length; ++i)
        oss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];

    return oss.str();
}


class Node {
public:
    string value;   // hash of this node
    string data;    // original transaction data (for leaves)
    Node* left;
    Node* right;

    // Leaf node
    Node(const string& d) : data(d), left(nullptr), right(nullptr) {
        value = sha256(d);
    }

    // Internal node
    Node(Node* l, Node* r) : left(l), right(r) {
        value = sha256(l->value + r->value);
        data = "";
    }

    bool isLeaf() const { return left == nullptr && right == nullptr; }
};

Node* buildMerkleTree(vector<Node*>& leaves) {
    if (leaves.empty()) return nullptr;

    vector<Node*> currentLevel = leaves;

    while (currentLevel.size() > 1) {
        vector<Node*> parents;
        for (size_t i = 0; i < currentLevel.size(); i += 2) {
            Node* left = currentLevel[i];
            Node* right = (i + 1 < currentLevel.size()) ? currentLevel[i + 1] : currentLevel[i]; // duplicate if odd
            parents.push_back(new Node(left, right));
        }
        currentLevel = parents;
    }

    return currentLevel[0]; // root
}

void printTree(Node* node, const string& prefix = "", bool isLeft = true) {
    if (!node) return;

    cout << prefix;

    if (!prefix.empty()) {
        cout << (isLeft ? "├── " : "└── ");
    }

    if (node->isLeaf()) {
        cout << "[Leaf] \"" << node->data << "\" → " << node->value << endl;
    } else {
        cout << "[Node] " << node->value << endl;
    }

    if (node->left || node->right) {
        string newPrefix = prefix + (isLeft ? "│   " : "    ");
        printTree(node->left, newPrefix, true);
        printTree(node->right, newPrefix, false);
    }
}

void freeTree(Node* node) {
    if (!node) return;
    freeTree(node->left);
    freeTree(node->right);
    delete node;
}

int main() {
    vector<string> transactions = {
        "Transaction#1",
        "Transaction#2",
        "Transaction#3",
        "Transaction#4",
    };

    // Create leaf nodes
    vector<Node*> leaves;
    for (auto& t : transactions) {
        leaves.push_back(new Node(t));
    }

    // Build Merkle tree
    Node* root = buildMerkleTree(leaves);

    // Print Merkle root
    cout << "\nMerkle Root: " << root->value << "\n\n";

    // Print tree structure
    cout << "Full Merkle Tree:\n";
    printTree(root);

    // Free memory
    freeTree(root);

    return 0;
}
