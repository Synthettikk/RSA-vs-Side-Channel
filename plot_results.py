import pandas as pd
import matplotlib.pyplot as plt

df = pd.read_csv("results.csv", skipinitialspace=True)

plt.figure(figsize=(8,5))
plt.plot(df["keybits"], df["mpz_powm_ms"], marker='o', label="mpz_powm")
plt.plot(df["keybits"], df["mpz_powm_sec_ms"], marker='o', label="mpz_powm_sec")
plt.plot(df["keybits"], df["sq_and_mult"], marker='s', label="sq_and_mult")
plt.plot(df["keybits"], df["montgomery_ladder_ms"], marker='o', label="montgomery")
plt.plot(df["keybits"], df["montgomery_fault_ms"], marker='o', label="montgomery with fault prevention")
plt.plot(df["keybits"], df["rsa_decrypt_ms"], marker='^', label="rsa_decrypt")

plt.xlabel("Key size (bits)")
plt.ylabel("Time (ms)")
plt.title("RSA exponentiations: timing comparison")
plt.grid(True, linestyle='--', alpha=0.5)
plt.legend()
plt.tight_layout()
plt.savefig("rsa_times.png", dpi=300)
plt.show()
