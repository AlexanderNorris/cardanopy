# CardanoPy
Cardano Shelley Network Mini Protocol implementations in Python

```
from cardano import Node
node = Node('relay1-mainnet.nasec.co.uk', 3000)
INFO:root:Opening a TCP connection to relay1-mainnet.nasec.co.uk:3000
>>> node.handshake()
INFO:root:>>> Version Proposal: [0, {1: 764824073, 2: 764824073, 3: 764824073, 4: [764824073, False], 5: [764824073, False], 6: [764824073, False], 7: [764824073, False], 8: [764824073, False]}]
INFO:root:8
INFO:root:<<< Version: [1, 7, [764824073, False]]
```

At present few of the protocols are actually covered, please feel free to contribute.

## Mini Protocol Coverage
- Handshake Protocol - Complete
- Chain-Sync Protocol - Partial
- Block Fetch Protocol - X
- TxSubmission Protocol - X
- Keep Alive Mini Protocol - X
- Local Transaction Submission Mini Protocol - X
- Local State Query Mini Protocol - X
