#include <iostream>
#include <string>
#include <vector>
#include <sstream>
#include <iomanip>
#include <chrono>
#include <random>
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

    ostringstream oss;
    for (unsigned int i = 0; i < length; ++i)
        oss << hex << setw(2) << setfill('0') << (int)hash[i];
    return oss.str();
}

struct Transaction {
    string id;
    string sender;
    string receiver;
    double amount;

    string toString() const {
        return id + ":" + sender + "->" + receiver + ":" + to_string(amount);
    }
};

class Node {
public:
    string value;
    string data;
    Node* left;
    Node* right;

    Node(const string &d) : data(d), left(nullptr), right(nullptr) {
        value = sha256(d);
    }

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
            Node* right = (i + 1 < level.size()) ? level[i + 1] : level[i];
            next.push_back(new Node(left, right));
        }
        level = next;
    }
    return level[0];
}

void printTree(Node* node, const string& prefix = "", bool isLeft = true) {
    if (!node) return;
    cout << prefix;
    if (!prefix.empty()) cout << (isLeft ? "├── " : "└── ");
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

class BlockPoW {
public:
    int index;
    string prevHash;
    vector<Transaction> transactions;
    string merkleRoot;
    long long timestamp;
    long long nonce;
    string hash;

    BlockPoW(int idx, const string &prev, const vector<Transaction> &txs)
        : index(idx), prevHash(prev), transactions(txs), nonce(0) {
        timestamp = chrono::duration_cast<chrono::milliseconds>(
                        chrono::system_clock::now().time_since_epoch()
                    ).count();
        merkleRoot = computeMerkleRoot();
        hash = calculateHash();
    }

    string computeMerkleRoot() {
        vector<Node*> leaves;
        for (auto &tx : transactions)
            leaves.push_back(new Node(tx.toString()));
        Node* root = buildMerkleTree(leaves);
        string rootHash = root ? root->value : "";
        cout << "Merkle Tree for Block " << index << ":\n";
        printTree(root);
        freeTree(root);
        return rootHash;
    }

    string calculateHash() const {
        return sha256(to_string(index) + prevHash + merkleRoot + to_string(timestamp) + to_string(nonce));
    }

    void mineBlock(int difficulty) {
        string target(difficulty, '0');
        do {
            nonce++;
            hash = calculateHash();
        } while (hash.substr(0, difficulty) != target);
    }
};

class BlockchainPoW {
public:
    vector<BlockPoW*> chain;
    int difficulty;

    BlockchainPoW(int diff) : difficulty(diff) {
        BlockPoW* genesis = new BlockPoW(0, "0", {{"Genesis","System","System",0}});
        genesis->mineBlock(difficulty);
        chain.push_back(genesis);
    }

    ~BlockchainPoW() {
        for (auto b : chain) delete b;
    }

    void addBlock(const vector<Transaction> &txs) {
        BlockPoW* prev = chain.back();
        BlockPoW* b = new BlockPoW(chain.size(), prev->hash, txs);

        auto start = chrono::high_resolution_clock::now();
        b->mineBlock(difficulty);
        auto end = chrono::high_resolution_clock::now();
        chrono::duration<double> elapsed = end - start;

        chain.push_back(b);
        cout << "Block " << b->index << " mined | Hash: " << b->hash.substr(0,20) << "...\n";
        cout << "Mining time: " << elapsed.count() << " s\n\n";
    }

    bool isChainValid() {
        for (size_t i = 1; i < chain.size(); i++) {
            if (chain[i]->prevHash != chain[i-1]->hash) return false;
            if (chain[i]->hash != chain[i]->calculateHash()) return false;
        }
        return true;
    }
};

struct Validator {
    string name;
    int stake;
};

class BlockPoS {
public:
    int index;
    string prevHash;
    vector<Transaction> transactions;
    string merkleRoot;
    long long timestamp;
    string hash;
    string validator;

    BlockPoS(int idx, const string &prev, const vector<Transaction> &txs, const string &vname)
        : index(idx), prevHash(prev), transactions(txs), validator(vname) {
        timestamp = chrono::duration_cast<chrono::milliseconds>(
                        chrono::system_clock::now().time_since_epoch()
                    ).count();
        merkleRoot = computeMerkleRoot();
        hash = calculateHash();
    }

    string computeMerkleRoot() {
        vector<Node*> leaves;
        for (auto &tx : transactions)
            leaves.push_back(new Node(tx.toString()));
        Node* root = buildMerkleTree(leaves);
        string rootHash = root ? root->value : "";
        cout << "Merkle Tree for Block " << index << ":\n";
        printTree(root);
        freeTree(root);
        return rootHash;
    }

    string calculateHash() const {
        return sha256(to_string(index) + prevHash + merkleRoot + to_string(timestamp) + validator);
    }
};

class BlockchainPoS {
public:
    vector<BlockPoS*> chain;
    vector<Validator> validators;

    BlockchainPoS(const vector<Validator> &vals) : validators(vals) {
        BlockPoS* genesis = new BlockPoS(0, "0", {{"Genesis","System","System",0}}, "System");
        chain.push_back(genesis);
    }

    ~BlockchainPoS() {
        for (auto b : chain) delete b;
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

    void addBlock(const vector<Transaction> &txs) {
        BlockPoS* prev = chain.back();
        Validator v = selectValidator();

        auto start = chrono::high_resolution_clock::now();
        BlockPoS* b = new BlockPoS(chain.size(), prev->hash, txs, v.name);
        auto end = chrono::high_resolution_clock::now();
        chrono::duration<double> elapsed = end - start;

        chain.push_back(b);

        cout << "Block " << b->index << " validated by " << b->validator
             << " | Hash: " << b->hash.substr(0,20) << "...\n";
        cout << "Validation time: " << elapsed.count() << " s\n\n";
    }

    bool isChainValid() {
        for (size_t i = 1; i < chain.size(); i++) {
            if (chain[i]->prevHash != chain[i-1]->hash) return false;
            if (chain[i]->hash != chain[i]->calculateHash()) return false;
        }
        return true;
    }
};

int main() {
    cout << "=== Proof of Work Blockchain ===\n";
    BlockchainPoW bcPoW(4);
    bcPoW.addBlock({{"TX1","Anas","Rachid",10},{"TX2","Rachid","Karim",5}});
    bcPoW.addBlock({{"TX3","Karim","Anas",7},{"TX4","Rachid","Anas",2}});

    cout << "Is PoW blockchain valid? " << (bcPoW.isChainValid() ? "Yes" : "No") << "\n\n";

    cout << "=== Proof of Stake Blockchain ===\n";
    vector<Validator> validators = {{"Anas",50},{"Rachid",30},{"Karim",20}};
    BlockchainPoS bcPoS(validators);
    bcPoS.addBlock({{"TX1","Anas","Rachid",10},{"TX2","Rachid","Karim",5}});
    bcPoS.addBlock({{"TX3","Karim","Anas",7},{"TX4","Rachid","Anas",2}});

    cout << "Is PoS blockchain valid? " << (bcPoS.isChainValid() ? "Yes" : "No") << "\n";

    return 0;
}
