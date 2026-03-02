package state

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"sync"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/tracing"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethdb/memorydb"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/ethereum/go-ethereum/trie"
)

// BalanceChangeEvent records a single balance modification during block processing.
type BalanceChangeEvent struct {
	Address       common.Address
	PrevBalance   string
	NewBalance    string
	Amount        string // positive for add, negative for sub
	Reason        tracing.BalanceChangeReason
	IsAdd         bool // true for add/set-increase, false for sub/set-decrease
}

// StateTransitionLogger writes JSONL records for each block's state transitions.
type StateTransitionLogger struct {
	mu   sync.Mutex
	file *os.File
}

// BlockTransitionLog is the top-level JSONL record written per block.
type BlockTransitionLog struct {
	BlockNumber   uint64                 `json:"block_number"`
	BlockHash     string                 `json:"block_hash"`
	ParentRoot    string                 `json:"parent_root"`
	ComputedRoot  string                 `json:"computed_root"`
	ExpectedRoot  string                 `json:"expected_root"`
	RootsMatch    bool                   `json:"roots_match"`
	AccountCount  int                    `json:"changed_account_count"`
	Accounts      []AccountTransitionLog `json:"accounts"`
	Errors        []string               `json:"errors,omitempty"`
}

// BalanceChangeLog records a single balance change event.
type BalanceChangeLog struct {
	PrevBalance string `json:"prev_balance"`
	NewBalance  string `json:"new_balance"`
	Amount      string `json:"amount"`
	Reason      string `json:"reason"`
}

// AccountTransitionLog records per-account state change details.
type AccountTransitionLog struct {
	Address           string             `json:"address"`
	MutationType      string             `json:"mutation_type"`
	BalanceBefore     string             `json:"balance_before"`
	BalanceAfter      string             `json:"balance_after"`
	NonceBefore       uint64             `json:"nonce_before"`
	NonceAfter        uint64             `json:"nonce_after"`
	BalanceChanges    []BalanceChangeLog `json:"balance_changes"`
	InMemProofValid   bool               `json:"in_mem_proof_valid"`
	InMemProof        []string           `json:"in_mem_proof"`
	DiskProofValid    bool               `json:"disk_proof_valid"`
	DiskProof         []string           `json:"disk_proof"`
	InMemDiskMatch    bool               `json:"in_mem_disk_match"`
	InMemProofError   string             `json:"in_mem_proof_error,omitempty"`
	DiskProofError    string             `json:"disk_proof_error,omitempty"`
	StateMismatchNote string             `json:"state_mismatch_note,omitempty"`
}

// proofList implements ethdb.KeyValueWriter and collects proof nodes in order.
type proofList [][]byte

func (p *proofList) Put(key []byte, value []byte) error {
	node := make([]byte, len(value))
	copy(node, value)
	*p = append(*p, node)
	return nil
}

func (p *proofList) Delete(key []byte) error {
	return nil
}

// toHexStrings converts proof nodes to hex-encoded strings.
func (p proofList) toHexStrings() []string {
	result := make([]string, len(p))
	for i, node := range p {
		result[i] = hexutil.Encode(node)
	}
	return result
}

// NewStateTransitionLogger creates a logger that appends JSONL to the given file path.
func NewStateTransitionLogger(filePath string) (*StateTransitionLogger, error) {
	f, err := os.OpenFile(filePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return nil, err
	}
	return &StateTransitionLogger{file: f}, nil
}

// Close closes the underlying log file.
func (l *StateTransitionLogger) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.file.Close()
}

func (l *StateTransitionLogger) write(record *BlockTransitionLog) {
	l.mu.Lock()
	defer l.mu.Unlock()

	data, err := json.Marshal(record)
	if err != nil {
		log.Error("Failed to marshal state transition log", "err", err)
		return
	}
	data = append(data, '\n')
	if _, err := l.file.Write(data); err != nil {
		log.Error("Failed to write state transition log", "err", err)
	}
}

// recordBalanceChange appends a balance change event to the StateDB's event log.
func (s *StateDB) recordBalanceChange(addr common.Address, prev, new string, amount string, reason tracing.BalanceChangeReason, isAdd bool) {
	s.balanceChangeEvents = append(s.balanceChangeEvents, BalanceChangeEvent{
		Address:     addr,
		PrevBalance: prev,
		NewBalance:  new,
		Amount:      amount,
		Reason:      reason,
		IsAdd:       isAdd,
	})
}

// LogStateTransitions iterates over s.mutations, captures before/after balances,
// generates proofs from both in-memory and disk tries, verifies them, and writes
// a JSONL record to the logger.
//
// Must be called AFTER IntermediateRoot (so s.trie is populated) and BEFORE Commit.
func (s *StateDB) LogStateTransitions(
	logger *StateTransitionLogger,
	blockNumber uint64,
	blockHash common.Hash,
	expectedRoot common.Hash,
	parentRoot common.Hash,
) {
	if logger == nil {
		return
	}

	computedRoot := common.Hash{}
	if s.trie != nil {
		computedRoot = s.trie.Hash()
	}

	record := BlockTransitionLog{
		BlockNumber:  blockNumber,
		BlockHash:    blockHash.Hex(),
		ParentRoot:   parentRoot.Hex(),
		ComputedRoot: computedRoot.Hex(),
		ExpectedRoot: expectedRoot.Hex(),
		RootsMatch:   computedRoot == expectedRoot,
	}

	// Open a disk-backed trie from the parent root (pre-transition state).
	// We cannot open from computedRoot because those nodes haven't been committed yet.
	diskTrie, diskTrieErr := s.db.OpenTrie(s.originalRoot)
	if diskTrieErr != nil {
		record.Errors = append(record.Errors,
			"failed to open disk trie from parent root: "+diskTrieErr.Error())
	}

	// Index balance change events by address for quick lookup.
	changesByAddr := make(map[common.Address][]BalanceChangeEvent)
	for _, evt := range s.balanceChangeEvents {
		changesByAddr[evt.Address] = append(changesByAddr[evt.Address], evt)
	}

	var accounts []AccountTransitionLog
	for addr, m := range s.mutations {
		entry := AccountTransitionLog{
			Address: addr.Hex(),
		}
		if m.isDelete() {
			entry.MutationType = "deletion"
		} else {
			entry.MutationType = "update"
		}

		// --- Before balance (from stateObject.origin) ---
		obj := s.stateObjects[addr]
		if obj != nil && obj.origin != nil {
			entry.BalanceBefore = obj.origin.Balance.String()
			entry.NonceBefore = obj.origin.Nonce
		} else if destructed, ok := s.stateObjectsDestruct[addr]; ok && destructed.origin != nil {
			entry.BalanceBefore = destructed.origin.Balance.String()
			entry.NonceBefore = destructed.origin.Nonce
		} else {
			entry.BalanceBefore = "0"
			entry.NonceBefore = 0
		}

		// --- After balance (from stateObject.data) ---
		if obj != nil && !m.isDelete() {
			entry.BalanceAfter = obj.data.Balance.String()
			entry.NonceAfter = obj.data.Nonce
		} else {
			entry.BalanceAfter = "0"
			entry.NonceAfter = 0
		}

		// --- Fine-grained balance changes ---
		if events, ok := changesByAddr[addr]; ok {
			for _, evt := range events {
				entry.BalanceChanges = append(entry.BalanceChanges, BalanceChangeLog{
					PrevBalance: evt.PrevBalance,
					NewBalance:  evt.NewBalance,
					Amount:      evt.Amount,
					Reason:      evt.Reason.String(),
				})
			}
		}

		hashedKey := crypto.Keccak256(addr.Bytes())

		// --- In-memory trie proof (post-transition) ---
		if s.trie != nil {
			var proof proofList
			if err := s.trie.Prove(hashedKey, &proof); err != nil {
				entry.InMemProofError = err.Error()
			} else {
				entry.InMemProof = proof.toHexStrings()

				// Also verify with memorydb for correctness check
				verifyDB := memorydb.New()
				for _, node := range proof {
					hash := crypto.Keccak256Hash(node)
					verifyDB.Put(hash.Bytes(), node)
				}
				val, err := trie.VerifyProof(computedRoot, hashedKey, verifyDB)
				if err != nil {
					entry.InMemProofValid = false
					entry.InMemProofError = "verification failed: " + err.Error()
				} else {
					entry.InMemProofValid = true
					// Verify the RLP value matches the in-memory account for updates
					if !m.isDelete() && obj != nil {
						expectedRLP, rlpErr := rlp.EncodeToBytes(&obj.data)
						if rlpErr == nil && !bytes.Equal(val, expectedRLP) {
							entry.InMemProofError = fmt.Sprintf(
								"proof value does not match in-memory account RLP (val=%x)", val)
							entry.InMemProofValid = false
						}
					}
				}
			}
		} else {
			entry.InMemProofError = "in-memory trie is nil"
		}

		// --- Disk trie proof (from parent root, pre-transition) ---
		if diskTrie != nil {
			var proof proofList
			if err := diskTrie.Prove(hashedKey, &proof); err != nil {
				entry.DiskProofError = err.Error()
			} else {
				entry.DiskProof = proof.toHexStrings()

				verifyDB := memorydb.New()
				for _, node := range proof {
					hash := crypto.Keccak256Hash(node)
					verifyDB.Put(hash.Bytes(), node)
				}
				val, err := trie.VerifyProof(s.originalRoot, hashedKey, verifyDB)
				if err != nil {
					entry.DiskProofValid = false
					entry.DiskProofError = "verification failed: " + err.Error()
				} else {
					entry.DiskProofValid = true
					// Disk value should match origin for existing accounts
					if obj != nil && obj.origin != nil {
						originRLP, rlpErr := rlp.EncodeToBytes(obj.origin)
						if rlpErr == nil && !bytes.Equal(val, originRLP) {
							entry.DiskProofError = fmt.Sprintf(
								"disk proof value does not match origin account (val=%x)", val)
							entry.DiskProofValid = false
						}
					}
				}
			}
		}

		// --- In-memory vs disk state comparison ---
		if s.trie != nil {
			inMemAcct, inMemErr := s.trie.GetAccount(addr)
			if inMemErr != nil {
				entry.StateMismatchNote = fmt.Sprintf("error reading in-mem trie: %v", inMemErr)
			} else if m.isDelete() {
				if inMemAcct != nil {
					entry.StateMismatchNote = "MISMATCH: account should be deleted but still in trie"
					entry.InMemDiskMatch = false
				} else {
					entry.InMemDiskMatch = true
				}
			} else if obj != nil {
				if inMemAcct == nil {
					entry.StateMismatchNote = "MISMATCH: updated account not found in in-memory trie"
					entry.InMemDiskMatch = false
				} else if inMemAcct.Balance.Cmp(obj.data.Balance) != 0 || inMemAcct.Nonce != obj.data.Nonce {
					entry.StateMismatchNote = fmt.Sprintf(
						"MISMATCH: trie balance=%s nonce=%d, stateObj balance=%s nonce=%d",
						inMemAcct.Balance, inMemAcct.Nonce, obj.data.Balance, obj.data.Nonce)
					entry.InMemDiskMatch = false
				} else {
					entry.InMemDiskMatch = true
				}
			}
		}

		accounts = append(accounts, entry)
	}

	record.Accounts = accounts
	record.AccountCount = len(accounts)

	logger.write(&record)
}
