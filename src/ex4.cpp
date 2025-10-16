#include <iostream>
#include <string>
#include <vector>
#include <sstream>
#include <iomanip>
#include <chrono>
#include <random>
#include <openssl/evp.h>

using namespace std;

// ====================== SHA256 ======================
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

    ostringstream oss;
    for (unsigned int i = 0; i < length; ++i)
        oss << hex << setw(2) << setfill('0') << (int)hash[i];
    return oss.str();
}

// ====================== Transaction ======================
struct Transaction {
    string id;
    string sender;
    string receiver;
    double amount;

    string toString() const {
        ostringstream oss;
        oss << id << ":" << sender << "->" << receiver << ":" << amount;
        return oss.str();
    }
};

// ====================== Merkle Tree ======================
class Node {
public:
    string value;
    string data;
    Node* left;
    Node* right;

    Node(const string &d) : data(d), left(nullptr), right(nullptr) { value = sha256(d); }
    Node(Node* l, Node* r) : left(l), right(r) { value = sha256(l->value + r->value); data = ""; }
    bool isLeaf() const { return left == nullptr && right == nullptr; }
};

Node* buildMerkleTree(vector<Node*> &leaves) {
    if (leaves.empty()) return nullptr;
    vector<Node*> level = leaves;
    while (level.size() > 1) {
        vector<Node*> next;
        for (size_t i = 0; i < level.size(); i += 2) {
            Node* left = level[i];
            Node* right = (i + 1 < level.size()) ? level[i + 1] : level[i];
            next.push_back(new Node(left, right));
        }
        level = next;
    }
    return level[0];
}

void printTree(Node* node, const string& prefix = "", bool isLeft = true) {
    if (!node) return;
    cout << prefix << (prefix.empty() ? "" : (isLeft ? "├── " : "└── "));
    if (node->isLeaf()) cout << "[Leaf] " << node->data << " → " << node->value << endl;
    else cout << "[Node] " << node->value << endl;
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

// ====================== Validators ======================
struct Validator {
    string name;
    int stake;
};

// ====================== Block ======================
class Block {
public:
    int index;
    string prevHash;
    vector<Transaction> transactions;
    string merkleRoot;
    long long timestamp;
    long long nonce = 0;
    string hash;
    string validator;
    bool isPoW;

    Block(int idx, const string &prev, const vector<Transaction> &txs, bool pow = true)
        : index(idx), prevHash(prev), transactions(txs), isPoW(pow) {
        timestamp = chrono::duration_cast<chrono::milliseconds>(
                        chrono::system_clock::now().time_since_epoch()).count();
        merkleRoot = computeMerkleRoot();
        hash = calculateHash();
    }

    string computeMerkleRoot() {
        vector<Node*> leaves;
        for (auto &tx : transactions) leaves.push_back(new Node(tx.toString()));
        Node* root = buildMerkleTree(leaves);
        string rootHash = root ? root->value : "";
        cout << "Merkle Tree for Block " << index << ":\n";
        printTree(root);
        freeTree(root);
        return rootHash;
    }

    string calculateHash() const {
        string data = to_string(index) + prevHash + merkleRoot + 
                      to_string(timestamp) + validator + to_string(nonce);
        return sha256(data);
    }

    void mineBlock(int difficulty) {
        string target(difficulty, '0');
        do {
            nonce++;
            hash = calculateHash();
        } while (hash.substr(0, difficulty) != target);
    }
};

// ====================== Blockchain ======================
class Blockchain {
public:
    vector<Block*> chain;
    vector<Validator> validators;
    int difficulty;
    vector<double> powTimes;
    vector<double> posTimes;

    Blockchain(int diff, const vector<Validator>& vals) : difficulty(diff), validators(vals) {
        Block* genesis = new Block(0, "0", {{"0","System","System",0}}, true);
        genesis->validator = "System";
        genesis->hash = genesis->calculateHash();
        chain.push_back(genesis);
    }

    ~Blockchain() {
        for (auto block : chain) delete block;
    }

    Validator selectValidator() {
        int totalStake = 0;
        for (auto &v : validators) totalStake += v.stake;

        random_device rd;
        mt19937 gen(rd());
        uniform_int_distribution<> dis(1, totalStake);

        int r = dis(gen);
        int cumulative = 0;
        for (auto &v : validators) {
            cumulative += v.stake;
            if (r <= cumulative) return v;
        }
        return validators.back();
    }

    void addBlock(const vector<Transaction> &txs, bool usePoW = true) {
        Block* prevBlock = chain.back();
        Block* newBlock = new Block(chain.size(), prevBlock->hash, txs, usePoW);

        auto start = chrono::high_resolution_clock::now();

        if (usePoW) {
            newBlock->mineBlock(difficulty);
            newBlock->validator = "PoW Miner";
        } else {
            Validator v = selectValidator();
            newBlock->validator = v.name;
            newBlock->hash = newBlock->calculateHash();
        }

        auto end = chrono::high_resolution_clock::now();
        chrono::duration<double> elapsed = end - start;

        if (usePoW) powTimes.push_back(elapsed.count());
        else posTimes.push_back(elapsed.count());

        chain.push_back(newBlock);

        cout << "Block " << newBlock->index
             << " | Validator: " << newBlock->validator
             << " | Hash: " << newBlock->hash.substr(0, 20) << "...\n";
        cout << "Validation time: " << elapsed.count() << " s\n\n";
    }

    bool isChainValid() {
        for (size_t i = 1; i < chain.size(); ++i) {
            Block* curr = chain[i];
            Block* prev = chain[i-1];
            if (curr->prevHash != prev->hash || curr->calculateHash() != curr->hash)
                return false;
        }
        return true;
    }

    void printSummary() {
        double totalPoW = 0, totalPoS = 0;
        for (double t : powTimes) totalPoW += t;
        for (double t : posTimes) totalPoS += t;
        cout << "\n=== Performance Summary ===\n";
        cout << "Total PoW blocks: " << powTimes.size() << ", Total time: " << totalPoW << " s, Avg: " << (powTimes.empty()?0:totalPoW/powTimes.size()) << " s\n";
        cout << "Total PoS blocks: " << posTimes.size() << ", Total time: " << totalPoS << " s, Avg: " << (posTimes.empty()?0:totalPoS/posTimes.size()) << " s\n";
    }
};

// ====================== Main ======================
int main() {
    vector<Validator> validators = {{"Alice",50},{"Bob",30},{"Carol",20}};
    Blockchain bc(4, validators); // difficulty 4 for PoW

    vector<Transaction> txs1 = {{"TX1","Alice","Bob",10},{"TX2","Bob","Carol",5}};
    vector<Transaction> txs2 = {{"TX3","Carol","Alice",7},{"TX4","Bob","Alice",2}};

    cout << "=== Adding blocks with PoW ===\n";
    bc.addBlock(txs1, true);
    bc.addBlock(txs2, true);

    cout << "=== Adding blocks with PoS ===\n";
    bc.addBlock(txs1, false);
    bc.addBlock(txs2, false);

    cout << "Is blockchain valid? " << (bc.isChainValid() ? "Yes" : "No") << "\n";

    bc.printSummary();

    return 0;
}
