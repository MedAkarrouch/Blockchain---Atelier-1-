#include <iostream>
#include <string>
#include <vector>
#include <sstream>
#include <iomanip>
#include <chrono>
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
    string value;  // hash
    string data;   // only for leaves
    Node* left;
    Node* right;

    // Leaf
    Node(const string &d) : data(d), left(nullptr), right(nullptr) {
        value = sha256(d);
    }

    // Internal
    Node(Node* l, Node* r) : left(l), right(r) {
        value = sha256(l->value + r->value);
        data = "";
    }

    bool isLeaf() const { return left == nullptr && right == nullptr; }
};

Node* buildMerkleTree(vector<Node*> &leaves) {
    if (leaves.empty()) return nullptr;

    vector<Node*> level = leaves;
    while (level.size() > 1) {
        vector<Node*> next;
        for (size_t i = 0; i < level.size(); i += 2) {
            Node* left = level[i];
            Node* right = (i + 1 < level.size()) ? level[i + 1] : level[i]; // duplicate if odd
            next.push_back(new Node(left, right));
        }
        level = next;
    }
    return level[0]; // root
}

class Block {
public:
    int index;
    string prevHash;
    vector<string> transactions;
    string merkleRoot;
    long long timestamp;
    long long nonce;
    string hash;

    Block(int idx, const string &prev, const vector<string> &txs)
        : index(idx), prevHash(prev), transactions(txs), nonce(0) {
        timestamp = chrono::duration_cast<chrono::milliseconds>(
                        chrono::system_clock::now().time_since_epoch()
                    ).count();
        merkleRoot = computeMerkleRoot();
        hash = calculateHash();
    }

    string computeMerkleRoot() {
        vector<Node*> leaves;
        for (auto &tx : transactions) {
            leaves.push_back(new Node(tx));
        }
        Node* root = buildMerkleTree(leaves);
        string rootHash = root ? root->value : "";
        return rootHash;
    }

    string calculateHash() const {
        string blockData = to_string(index) + prevHash + merkleRoot + 
                           to_string(timestamp) + to_string(nonce);
        return sha256(blockData);
    }

    void mineBlock(int difficulty) {
        string target(difficulty, '0');
        do {
            nonce++;
            hash = calculateHash();
        } while (hash.substr(0, difficulty) != target);
    }
};

class Blockchain {
public:
    vector<Block*> chain;
    int difficulty;

    Blockchain(int diff) : difficulty(diff) {
        Block* genesis = new Block(0, "0", {"Genesis Block"});
        genesis->mineBlock(difficulty);
        chain.push_back(genesis);
    }

    ~Blockchain() {
        for (auto block : chain) {
            delete block;
        }
    }

    void addBlock(const vector<string> &transactions) {
        Block* prevBlock = chain.back();
        Block* newBlock = new Block(chain.size(), prevBlock->hash, transactions);

        auto start = chrono::high_resolution_clock::now();
        newBlock->mineBlock(difficulty);
        auto end = chrono::high_resolution_clock::now();
        chrono::duration<double> elapsed = end - start;

        chain.push_back(newBlock);

        cout << "   Block " << newBlock->index 
             << " mined with hash: " << newBlock->hash.substr(0, 20) << "...\n";
        cout << "   Mining time: " << elapsed.count() << " s\n\n";
    }
};

int main() {
    vector<int> difficulties = {3, 4, 5}; 

    for (int diff : difficulties) {
        cout << "==============================\n";
        cout << "   Blockchain with difficulty " << diff << "\n";
        cout << "==============================\n";

        Blockchain bc(diff);

        bc.addBlock({"TX1", "TX2", "TX3"});
        bc.addBlock({"TX4", "TX5", "TX6", "TX7"});
    }

    return 0;
}
