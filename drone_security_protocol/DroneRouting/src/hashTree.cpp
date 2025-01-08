#include <routing/hashTree.hpp>

HashTree::TreeNode::TreeNode(const string& data, bool isHash) : left(nullptr), right(nullptr) { 
    if (isHash) {
        hash = data;
    } else {
        hash = hashString(data);
    }
}

string HashTree::TreeNode::hashString(const string& data) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((unsigned char *)data.c_str(), data.size(), hash);

    std::stringstream ss;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    }
    cout << ss.str() << endl;
    return ss.str();
}

string HashTree::hashNodes(const string& hash1, const string& hash2) {
    /* Hashes two values together, returns hash as string.
    Currently uses SHA256, but can change to lighterweight one later on.  */

    std::string combined = hash1 + hash2;
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((unsigned char *)combined.c_str(), combined.size(), hash);

    std::stringstream ss;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++)
    {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    }

    return ss.str();
}

string HashTree::hashSelf(const string& data) {
    /* Hashes the data, returns hash as string.
    Currently uses SHA256, but can change to lighterweight one later on.  */

    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((unsigned char *)data.c_str(), data.size(), hash);

    std::stringstream ss;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    }
    return ss.str();
}

/*HashesArray[root, leftNode, .... n - 1]*/
HashTree::HashTree(std::vector<string> hashesArray, int hopCount, string sourceAddr){
    /*Case 2: Along the path, we are rebuilding the tree.
    Arguments:
    1) The array of of hashes
    2) Current HopCount
    3) Address this message was recieved from 
    */
    int numElements = hashesArray.size();
    string lastCalculatedHash;
    string lastElementHash;
    TreeNode *currNode;

    if (hopCount == 1){ // edgecase for constructing from one hash
        lastElementHash = hashSelf(sourceAddr);
        currNode = new TreeNode(lastElementHash, true);
        root = currNode;
        return;
    } else if (hopCount == 2) { // edgecase for constructing from two hashes
        lastElementHash = hashSelf(sourceAddr);
        lastCalculatedHash = hashNodes(hashesArray[1], lastElementHash);
        currNode = new TreeNode(lastCalculatedHash, true);
        root = currNode;
        currNode = new TreeNode(hashesArray[1], true);
        root->setLeft(currNode);
        currNode = new TreeNode(lastElementHash, true);
        root->setRight(currNode);
    } else if ((numElements == 2 || numElements == 3) && (( ( (hopCount - 1) % 4 == 0) ) || ((hopCount - 2) % 4 == 0) ) ){ // edgecase for constructing leftmost subtree
        lastElementHash = hashSelf(sourceAddr);
        if (numElements == 2){
            lastCalculatedHash = hashNodes(lastElementHash, lastElementHash);
            currNode = new TreeNode(lastCalculatedHash, true);
            currNode->setLeft(new TreeNode(lastElementHash, true));
        } else {
            lastCalculatedHash = hashNodes(hashesArray[2], lastElementHash);
            currNode = new TreeNode(lastCalculatedHash, true);
            currNode->setLeft(new TreeNode(hashesArray[2], true));
            currNode->setRight(new TreeNode(lastElementHash, true));
        }

        
        TreeNode *prev = currNode;
        int levels = std::ceil(std::log2(hopCount));
        while (levels > 2){ // We skip past the leaf level and keep going until first level
            lastCalculatedHash = hashNodes(lastCalculatedHash, lastCalculatedHash);
            currNode = new TreeNode(lastCalculatedHash, true);
            currNode->setLeft(prev);
            prev = currNode;
            levels--;
        }

        lastCalculatedHash = hashNodes(hashesArray[1], lastCalculatedHash);
        currNode = new TreeNode(lastCalculatedHash, true);
        currNode->setLeft(new TreeNode(hashesArray[1], true));
        currNode->setRight(prev);
        root = currNode;
    } else if ((hopCount < 5) && ((hopCount % 4 == 0) || ((hopCount + 1) % 4 == 0))){ // edgecase for constructing rightmost subtree
        lastElementHash = hashSelf(sourceAddr);
        if (hopCount % 4 == 0){
            lastCalculatedHash = hashNodes(hashesArray[numElements - 1], lastElementHash);
            currNode = new TreeNode(lastCalculatedHash, true);
            currNode->setRight(new TreeNode(lastElementHash, true)); // do not require these to be added, can be removed for optimization
            currNode->setLeft(new TreeNode(hashesArray[numElements - 1], true));
            numElements--;
        } else {
            lastCalculatedHash = hashNodes(lastElementHash, lastElementHash);
            currNode = new TreeNode(lastCalculatedHash, true);
            currNode->setLeft(new TreeNode(lastElementHash, true));
        }

        TreeNode *prev = currNode;
        int levels = std::ceil(std::log2(hopCount));
        while (levels > 1){
            lastCalculatedHash = hashNodes(hashesArray[numElements - 1], lastCalculatedHash);
            currNode = new TreeNode(lastCalculatedHash, true);
            currNode->setRight(prev);
            currNode->setLeft(new TreeNode(hashesArray[numElements - 1], true));
            prev = currNode;
            levels--;
            numElements--;
        }
        root = currNode;

    } else { // generalized case
        TreeNode* prev;
        int prevLevel = hopCount;
        lastElementHash = hashSelf(sourceAddr);
        if (prevLevel % 2 == 1){
            lastCalculatedHash = hashNodes(lastElementHash, lastElementHash);
            currNode = new TreeNode(lastCalculatedHash, true);
            currNode->setLeft(new TreeNode(lastElementHash, true));
        } else {
            lastCalculatedHash = hashNodes(hashesArray[numElements - 1], lastElementHash);
            currNode = new TreeNode(lastCalculatedHash, true);
            currNode->setLeft(new TreeNode(hashesArray[numElements - 1], true));
            currNode->setRight(new TreeNode(lastElementHash, true));
            numElements--;
        }
        prev = currNode;
        
        int levels = std::ceil(std::log2(hopCount));
        prevLevel = std::ceil((prevLevel / 2.0));
        while (levels > 2){ // skip leaf & root
            if (prevLevel % 2 == 1){
                lastCalculatedHash = hashNodes(lastCalculatedHash, lastCalculatedHash);
                currNode = new TreeNode(lastCalculatedHash, true);
                currNode->setLeft(prev);
            } else {
                lastCalculatedHash = hashNodes(hashesArray[numElements - 1], lastCalculatedHash);
                currNode = new TreeNode(lastCalculatedHash, true);
                currNode->setLeft(new TreeNode(hashesArray[numElements - 1], true));
                currNode->setRight(prev);
                numElements--;
            }
            prev = currNode;
            levels--;
            prevLevel = std::ceil((prevLevel / 2));
        }
        // root case
        lastCalculatedHash = hashNodes(hashesArray[1], lastCalculatedHash);
        root = new TreeNode(lastCalculatedHash, true);
        root->setLeft(new TreeNode(hashesArray[1], true));
        root->setRight(prev);

        /* 
        function to determine if subtree is left or right(hopCount):
            log2(hopCount) = n
            2^n / 2 = y
            If hopCount > (y + y/2): in right subtree
            else in left subtree
            return true if in right, false if in left
        
        while level > 1:
        Determine what subtree current element is in
            if left: hash self
            if right: hash with n, where n is the last element in the hasharray
        Move up one level, determine that subtree
            if left: hash self
            if right: hash with n - 1, where n is second to last element
        etc, etc.*/
    }

    std::cout << "HashTree created" << std::endl;
}

bool HashTree::verifyTree(string& recvHash){
    /* Verifies the tree via checking root hash with calculated root. */
    if (recvHash == root->hash){
        return true;
    }
    return false;
}

void HashTree::addSelf(const string& droneID, const int& incomingHopCount){
    /* Adds a new node to the tree. 
    Takes in self drone id and the hopCount after adding the currentNode*/

    int leafLevel = std::ceil(std::log2(incomingHopCount));
    int totalAvailableNodes = std::pow(2, leafLevel) / 2;
    
    // Edge Case: Incoming Hop Count is 2
    if (incomingHopCount == 2){
        this->getRoot()->left = new TreeNode(this->getRoot()->getHash(), true);
        this->getRoot()->right = new TreeNode(hashSelf(droneID), true);
        this->getRoot()->updateHash(hashNodes(this->getRoot()->left->getHash(), this->getRoot()->right->getHash()));
        return;
    }

    // Edge Case: We must generate a new tree (new root)
    int n = incomingHopCount - 1;
    if ((n & (n - 1)) == 0) { // Check if its a power of 2
        TreeNode* newRoot = new TreeNode("ERR: TEMP ROOT HASH", true);
        TreeNode* newRight = new TreeNode("ERR: NULL HASH", true);
        newRoot->left = this->getRoot(); newRoot->right = newRight; this->setRoot(newRoot); 
        
    }

    string finalHash = recalculate(this->getRoot()->right, (totalAvailableNodes / 2), totalAvailableNodes + 1, totalAvailableNodes + (totalAvailableNodes / 2) + 1, leafLevel - 1, incomingHopCount, droneID);
    string rootHash = hashNodes(this->getRoot()->left->getHash(), finalHash);
    this->getRoot()->updateHash(rootHash);
    // cout << "This is the final root hash: " << rootHash << endl;
}

string HashTree::recalculate(TreeNode* node, const int& nodesAvail, const int& leftIndex, const int& rightIndex, const int& leafLevel, const int& incomingHopCount, const string& droneID){
    /* Parameters: A node (starts with the root), (Int) leafLevel left to go in tree before we reach leaves
    Recursive function to recalculate a node, given that its children nodes have been updated
    Returns a string of the newly calculated hash*/

    string newHash;
    bool lrflag; // true = left

    // Generalized case: calculate the range and choose which path to choose based on range
    if (leafLevel > 1) {
        if (incomingHopCount >= rightIndex){ // Enter right tree
            if (node->right == nullptr) node->right = new TreeNode("ERR: NULL HASH", true);
            newHash = recalculate(node->right, nodesAvail / 2, leftIndex + (nodesAvail / 2), rightIndex, leafLevel - 1, incomingHopCount, droneID);
            lrflag = false;
        } else {
            if (node->left == nullptr) node->left = new TreeNode("ERR: NULL HASH", true);
            newHash = recalculate(node->left, nodesAvail / 2, leftIndex, rightIndex - (nodesAvail / 2), leafLevel - 1, incomingHopCount, droneID);
            lrflag = true;
        }
    }

    if (leafLevel == 1) { // base case: we are parent nodes of leaf
        // Check if we are a (new) left node or we are a right node
        // Need to create the new hash & nodes, then update self node
        newHash = hashSelf(droneID);

        if (incomingHopCount % 2 == 0) {       
            node->setRight(new TreeNode(newHash, true));
            lrflag = false;
        }
        else {   
            node->setLeft(new TreeNode(newHash, true));
            lrflag = true;   
        }
    }

    // case: we are a node that needs to be recalculated
    if (lrflag) newHash = hashNodes(newHash, newHash); 
    else newHash = hashNodes(node->left->getHash(), newHash);
    node->updateHash(newHash);

    return newHash;
}

// bool HashTree::checkSubtreeDirection(const int& hopCount){
//     /*Determines if the current node is in the left or right subtree
//     Returns true if left, false if right*/
//     double n = std::ceil(std::log2(hopCount));
//     double y = std::pow(2, n) / 2;
//     if (hopCount > (y + y/2)){ // if greater than the middle point, in right subtree
//         return false;
//     }
//     return true;
// }

std::vector<string> HashTree::toVector(){
    /*Returns a vector of only the elements required to rebuild the tree*/
    std::vector<string> hashes;
    hashes.push_back(root->hash);
    TreeNode* currNode = root;
    TreeNode* leftNode;
    while(currNode->left != nullptr && currNode->right != nullptr){
        leftNode = currNode->left;
        hashes.push_back(leftNode->hash);
        currNode = currNode->right;
    } // Need to make the case where the right node is null (we had to duplicate nodes to finish tree)

    for (const auto& hash : hashes) {
        std::cout << hash << std::endl;
    }

    return hashes;
}