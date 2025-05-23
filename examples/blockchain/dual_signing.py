# 区块链双签名示例

def build_transaction(receiver):
    # 构造交易数据（伪实现）
    return {"receiver": receiver, "amount": 100, "nonce": 1}

def sign_with_dilithium(tx):
    # 伪签名，实际应调用 PQC 库
    return b"pq_signature"

def sign_with_ecdsa(tx):
    # 伪签名，实际应调用 ECDSA 库
    return b"legacy_signature"

def broadcast(tx_signed):
    # 伪广播，实际应调用区块链网络
    print(f"Broadcast: {tx_signed}")

if __name__ == "__main__":
    tx = build_transaction(receiver="0xABCDEF...")
    tx_signed = sign_with_dilithium(tx) + sign_with_ecdsa(tx)
    broadcast(tx_signed)