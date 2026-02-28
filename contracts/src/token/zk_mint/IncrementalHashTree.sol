// SPDX-License-Identifier: LicenseRef-VPL WITH AGPL-3.0-only
pragma solidity ^0.8.4;

/**
  This struct encodes all information representing the state of the hash tree.

  @param size The current number of leaves in the tree.
  @param depth The current depth of the tree. The semantics of this
    implementation are such that as the depth increases, the root of the tree is
    always at level `depth` and leaves are at level zero.
  @param lastLeftChild A mapping from each level of the tree to the node value
    of the last left child on that level. This is used for efficient inserts,
    updates, and root calculations.
  @param leaves A mapping from leaf values to their respective indices in the
    tree. This facilitates checks for leaf existence and retrieval of leaf
    positions.
  @param hash The tree's hash function.
*/
struct HashTree {
  uint256 size;
  uint256 depth;
  mapping (
    uint256 _level => uint256 _value
  ) lastLeftChild;
  mapping (
    uint256 _value => uint256 _index
  ) leaves;
  function(uint256[2] memory) view returns (uint256) hash;
}

/// An error emitted when a leaf value equals or exceeds the BN254 scalar field.
error LeafGreaterThanHasherLimit ();

/// An error emitted when a leaf value is zero, which is reserved as a sentinel.
error LeafCannotBeZero ();

/// An error emitted when attempting to insert a leaf that already exists.
error LeafAlreadyExists ();

/// An error emitted when looking up a leaf that has not been inserted.
error LeafDoesNotExist ();

// The order of the BN254 scalar field. All leaf values must be less than this.
uint256 constant SNARK_SCALAR_FIELD =
  21888242871839275222246405745257275088548364400416034343698204186575808495617;

/**
  @custom:benediction DEVS BENEDICAT ET PROTEGAT CONTRACTVM MEVM
  @title An appeend-only incremental binary hash tree.
  @author ZK-Kit
  @custom:blame Tim Clancy <tim-clancy.eth>
  @custom:terry "Is this too much voodoo for the next ten centuries?"
  @custom:preserve

  This contract is based on "zk-kit-lean-imt-custom-hash v2.1.1".

  This supplies a performant incremental binary hash tree with dynamic depth. It
  eliminates the use of zeroes as placeholder nodes. When a node does not have a
  right child, that node's value becomes that of its left child. The depth is
  updated based on the number of leaves in the tree, resulting in significantly
  fewer hashes.

  The tree is append-only. Leaves are assigned consecutive indices starting
  from zero. Level zero is the leaf layer; level `depth` is the root. At each
  level, nodes are paired left-right and hashed to produce a parent one level
  up. Given that the tree only appends, inserting a new leaf only requires
  recomputing nodes along the path from that leaf to the root.

  The `lastLeftChild` mapping caches the most recent left child at each level
  that does not yet have a right sibling. When a future right sibling arrives at
  the same level, it pairs with the cached value to produce their parent. The
  bit decomposition of the leaf's index determines the path: bit `level` being
  zero means the ancestor at that level is a left child (cache it), and one
  means it is a right child (hash it with the cached left sibling).

  @custom:date February 24th, 2026.
*/
library IncrementalHashTree {

  /**
    Retrieve the root of the tree.

    @param _tree The tree to check.

    @return _ The tree's root.
  */
  function root (
    HashTree storage _tree
  ) internal view returns (uint256) {
    return _tree.lastLeftChild[_tree.depth];
  }

  /**
    Check if a particular leaf value exists in the tree.

    @param _tree The tree to check.
    @param _leaf The leaf value to check for.

    @return _ Whether or not `_leaf` is in the tree.
  */
  function has (
    HashTree storage _tree,
    uint256 _leaf
  ) internal view returns (bool) {
    return _tree.leaves[_leaf] != 0;
  }

  /**
    Retrieve the index of a given leaf in the tree.

    @param _tree The tree to check.
    @param _leaf The leaf value to retrieve the index for.

    @return _ The index of `_leaf` in the tree, reverting if not present.
  */
  function indexOf (
    HashTree storage _tree,
    uint256 _leaf
  ) internal view returns (uint256) {
    if (_tree.leaves[_leaf] == 0) {
      revert LeafDoesNotExist();
    }
    return _tree.leaves[_leaf] - 1;
  }

  /**
    Inserts a new leaf into the incremental hash tree.

    @param _tree A storage reference to the hash tree's data.
    @param _leaf The value of the new leaf to insert.

    @return _ The new hash of the tree's root after the leaf has been inserted.
  */
  function insert (
    HashTree storage _tree,
    uint256 _leaf
  ) internal returns (uint256) {

    // Verify that the leaf value is valid to insert.
    if (_leaf >= SNARK_SCALAR_FIELD) {
      revert LeafGreaterThanHasherLimit();
    } else if (_leaf == 0) {
      revert LeafCannotBeZero();
    } else if (has(_tree, _leaf)) {
      revert LeafAlreadyExists();
    }

    // Cache the tree's hash function, size, and depth to optimize gas.
    function(uint256[2] memory) view returns (uint256) _hash = _tree.hash;
    uint256 _index = _tree.size;
    uint256 _treeDepth = _tree.depth;

    /*
      A new single insertion can increase a tree's depth by at most one, and
      only if the number of leaves supported by the current depth is less than
      the number of leaves which must be supported after insertion.
    */
    if (2 ** _treeDepth < _index + 1) {
      ++_treeDepth;
    }
    _tree.depth = _treeDepth;

    // Iterate through each level of the tree to recompute the path to the root.
    uint256 _root = _leaf;
    for (uint256 _level = 0; _level < _treeDepth; ) {

      /*
        If bit `_level` of `_index` is one, this node is a right child. Its left
        sibling was already inserted and cached in `lastLeftChild[_level]`, so
        hash the two together to produce the parent.
      */
      if ((_index >> _level) & 1 == 1) {
        _root = _hash([_tree.lastLeftChild[_level], _root]);

      /*
        Otherwise this node is a left child. Its right sibling does not exist
        yet, so cache this node's value as the last left child for this level; a
        future insertion will use it as the left input to the hash.
      */
      } else {
        _tree.lastLeftChild[_level] = _root;
      }
      unchecked {
        ++_level;
      }
    }

    // Update the tree and return the new root.
    _tree.size = ++_index;
    _tree.lastLeftChild[_treeDepth] = _root;
    _tree.leaves[_leaf] = _index;
    return _root;
  }

  /**
    Inserts many leaves into the incremental hash tree.

    @param _tree A storage reference to the hash tree's data.
    @param _leaves The values of the new leaves to insert.

    @return _ The new hash of the root after all leaves have been inserted.
  */
  function insertMany (
    HashTree storage _tree,
    uint256[] memory _leaves
  ) internal returns (uint256) {

    // Verify that all leaf values are valid to insert; cache the tree size.
    uint256 _treeSize = _tree.size;
    for (uint256 i = 0; i < _leaves.length; ) {
      if (_leaves[i] >= SNARK_SCALAR_FIELD) {
        revert LeafGreaterThanHasherLimit();
      } else if (_leaves[i] == 0) {
        revert LeafCannotBeZero();
      } else if (has(_tree, _leaves[i])) {
        revert LeafAlreadyExists();
      }
      _tree.leaves[_leaves[i]] = _treeSize + 1 + i;
      unchecked {
        ++i;
      }
    }

    // Cache the tree's hash function and depth to optimize gas.
    function(uint256[2] memory) view returns (uint256) _hash = _tree.hash;
    uint256 _treeDepth = _tree.depth;

    /*
      Create an array to save the nodes that will be used to create the next
      level of the tree.
    */
    uint256[] memory _currentLevelNewNodes;
    _currentLevelNewNodes = _leaves;

    /*
      Calculate the depth of the tree after adding the new values. Unlike the
      `insert` function, we need to loop here as multiple insertions may
      increase the tree's depth more than once.
    */
    while (2 ** _treeDepth < _treeSize + _leaves.length) {
      ++_treeDepth;
    }
    _tree.depth = _treeDepth;

    // Track the first index to change in every level.
    uint256 _currentLevelStartIndex = _treeSize;

    // Track the size of the tree down to the current level.
    uint256 _currentLevelSize = _treeSize + _leaves.length;

    /*
      Track the index where changes begin at the next level. Remember:
      higher-numbered levels smaller and higher up the tree.
    */
    uint256 _nextLevelStartIndex = _currentLevelStartIndex >> 1;

    // Track the size of the next level.
    uint256 _nextLevelSize = ((_currentLevelSize - 1) >> 1) + 1;

    // Iterate up through each level of the tree to recompute hashes.
    for (uint256 _level = 0; _level < _treeDepth; ) {

      // Calculate the number of nodes that will be updated on the next level.
      uint256 _newNodeCount = _nextLevelSize - _nextLevelStartIndex;
      uint256[] memory _nextLevelNewNodes = new uint256[](_newNodeCount);
      for (uint256 i = 0; i < _newNodeCount; ) {

        // Pack left and right nodes in one array to save on stack size.
        uint256[2] memory _hashInput;

        /*
          For every updated node of the next level, compute the index of the
          left child on the current level. If there is a child predating this
          batch insertion, use the cached value.
        */
        if ((i + _nextLevelStartIndex) * 2 < _currentLevelStartIndex) {
          _hashInput[0] = _tree.lastLeftChild[_level];

        // Otherwise, look up the value of the left child based on its index.
        } else {
          _hashInput[0] = _currentLevelNewNodes[
            (i + _nextLevelStartIndex) * 2 - _currentLevelStartIndex
          ];
        }

        // Assign the right child (the very next index) if it exists.
        if ((i + _nextLevelStartIndex) * 2 + 1 < _currentLevelSize) {
          _hashInput[1] = _currentLevelNewNodes[
            (i + _nextLevelStartIndex) * 2 + 1 - _currentLevelStartIndex
          ];
        }

        /*
          If the node has a right child, hash the pair. Otherwise the parent
          adopts the left child's value directly.
        */
        if (_hashInput[1] != 0) {
          _nextLevelNewNodes[i] = _hash(_hashInput);
        } else {
          _nextLevelNewNodes[i] = _hashInput[0];
        }
        unchecked {
          ++i;
        }
      }

      /*
        Update `lastLeftChild` for this level. If `currentLevelSize` is odd, the
        last node in the array is an unpaired left child. If even with more than
        one node, the last node is a right child that is already paired, so we
        take the second-to-last node. If even with exactly one node, the cached
        value from before the batch insertion is still correct because we are
        only inserting a single right child.
      */
      if (_currentLevelSize & 1 == 1) {
        _tree.lastLeftChild[_level] = _currentLevelNewNodes[
          _currentLevelNewNodes.length - 1
        ];
      } else if (_currentLevelNewNodes.length > 1) {
        _tree.lastLeftChild[_level] = _currentLevelNewNodes[
          _currentLevelNewNodes.length - 2
        ];
      }
      _currentLevelStartIndex = _nextLevelStartIndex;

      // Calculate the starting index of the next level.
      _nextLevelStartIndex >>= 1;

      // Update the next array that will be used to calculate the next level.
      _currentLevelNewNodes = _nextLevelNewNodes;
      _currentLevelSize = _nextLevelSize;

      /*
        Calculate the size of the next level. The size of the next level is
        (currentLevelSize - 1) / 2 + 1.
      */
      _nextLevelSize = ((_nextLevelSize - 1) >> 1) + 1;
      unchecked {
        ++_level;
      }
    }

    // Update tree size, root, and return the new root.
    _tree.size = _treeSize + _leaves.length;
    _tree.lastLeftChild[_treeDepth] = _currentLevelNewNodes[0];
    return _currentLevelNewNodes[0];
  }
}

