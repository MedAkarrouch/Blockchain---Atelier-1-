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



class Block {
public:
    int index;
    string prevHash;
    vector<string> transactions;
    string merkleRoot;
    long long timestamp;
    string hash;
    string validator;

    Block(int idx, const string &prev, const vector<string> &txs)
        : index(idx), prevHash(prev), transactions(txs) {
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
        string blockData = to_string(index) + prevHash + merkleRoot + to_string(timestamp) + validator;
        return sha256(blockData);
    }
};


struct Validator {
    string name;
    int stake;
};


class BlockchainPoS {
public:
    vector<Block*> chain;
    vector<Validator> validators;

    BlockchainPoS(const vector<Validator> &vals) : validators(vals) {
        Block* genesis = new Block(0, "0", {"Genesis Block"});
        genesis->validator = "System";
        genesis->hash = genesis->calculateHash();
        chain.push_back(genesis);
    }

    ~BlockchainPoS() {
        for (auto block : chain)
            delete block;
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
            if (r <= cumulative)
                return v;
        }
        return validators.back(); // fallback
    }

    void addBlock(const vector<string> &transactions) {
        Block* prevBlock = chain.back();
        Block* newBlock = new Block(chain.size(), prevBlock->hash, transactions);

        auto start = chrono::high_resolution_clock::now();
        Validator v = selectValidator();
        newBlock->validator = v.name;
        newBlock->hash = newBlock->calculateHash();
        auto end = chrono::high_resolution_clock::now();
        chrono::duration<double> elapsed = end - start;

        chain.push_back(newBlock);

        cout << "Block " << newBlock->index 
             << " validated by " << newBlock->validator
             << " | Hash: " << newBlock->hash.substr(0,20) << "...\n";
        cout << "Validation time: " << elapsed.count() << " s\n\n";
    }
};


int main() {
    vector<Validator> validators = {
        {"Alice", 50},
        {"Bob", 30},
        {"Carol", 20}
    };

    BlockchainPoS bc(validators);

    bc.addBlock({"TX1", "TX2", "TX3"});
    bc.addBlock({"TX4", "TX5", "TX6", "TX7"});
    bc.addBlock({"TX8", "TX9"});

    return 0;
}
