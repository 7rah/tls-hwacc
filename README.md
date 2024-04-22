# 编译运行

下载 mipsel-linux-muslsf-cross 到目录下，具体参考下面的文章。

[https://harrychen.xyz/2023/09/03/cross-compile-rust-to-mipsel/](https://harrychen.xyz/2023/09/03/cross-compile-rust-to-mipsel/)

```rust
# 跨平台编译，需要 rust-nightly 版本，因为我们要自行编译标准库
cargo build --target mipsel-unknown-linux-musl \
            -Zbuild-std=std,panic_abort --release
        
```

# 背景

MT7621 SoC 配备了 Mediatek EIP93 加密驱动，支持多种加密算法的硬件加速，加速效果显著。例如，使用纯 CPU 处理 aes-256-ctr 加密算法时的速度为 8110 KB/s，而启用硬件加速后速度可提升至 41.7 MB/s。因此，我们希望能将 TLS 加密算法中的对称加密部分卸载到硬件实现上。

```
# 使用硬件加速前
type             16 bytes     64 bytes    256 bytes   1024 bytes   8192 bytes  16384 bytes

aes-128-ecb      11510.47k    13501.51k    14126.95k    14294.16k    14340.08k    14337.36k
aes-256-ecb       8869.99k    10002.43k    10339.42k    10424.05k    10448.20k    10450.92k

aes-128-cbc       8979.48k    11176.46k    11904.00k    12101.57k    12160.09k    12160.09k
aes-256-cbc       7298.06k     8667.13k     9099.23k     9213.62k     9247.98k     9242.54k

aes-128-ctr       8287.57k     9700.27k    10123.82k    10234.90k    10268.58k    10265.86k
aes-256-ctr       6825.28k     7755.59k     8022.75k     8094.02k     8115.80k     8110.35k

# 使用了硬件加速后
# Tests are approximate using memory only (no storage IO).
# Algorithm |       Key |      Encryption |      Decryption
    aes-ecb        128b        42.1 MiB/s        42.0 MiB/s
    aes-ecb        256b        33.9 MiB/s        33.8 MiB/s
    aes-cbc        128b        41.3 MiB/s        41.6 MiB/s
    aes-cbc        256b        33.3 MiB/s        33.5 MiB/s
    aes-ctr        128b        41.7 MiB/s        41.7 MiB/s
    aes-ctr        256b        33.8 MiB/s        33.7 MiB/s
    aes-xts        256b        28.3 MiB/s        28.5 MiB/s
    aes-xts        512b        24.5 MiB/s        24.5 MiB/s

```

但是目前的密码学库（如 OpenSSL），可以调用硬件加速如 AES-CTR 的 AES 分组实现，但是对于常见的 AEAD 加密（Authenticated Encryption with Associated Data  是一种同时具备保密性，完整性和可认证性的加密形式，可以同时对信息做加密和认证），比如 TLS 1.3 中常用的 AES-256-GCM ，OpenSSL 库却做不到将 aes-ctr 的计算卸载到硬件上。而且，路由器固件中提供的 OpenSSL 库最高只支持 TLS 1.2 ，不支持 TLS 1.3，因此，我们需要一个新实现，能支持将 AES-256-GCM 加密套件中的 AES-CTR 卸载到硬件上，且支持 TLS 1.3。

与 TLS 1.2 相比， TLS1.3 中废除了非常多的加密算法，最后只保留五个加密套件:

- TLS_AES_128_GCM_SHA256（服务器端要求必须实现）
- TLS_AES_256_GCM_SHA384（服务器端要求必须实现）
- TLS_CHACHA20_POLY1305_SHA256（服务器端要求必须实现）
- TLS_AES_128_CCM_SHA256（不强制要求，OpenSSL 中默认不开启）
- TLS_AES_128_CCM_8_SHA256（不强制要求，OpenSSL 中默认不开启）

以路由器已有的硬件加密算法，其实实现 TLS_AES_128_CCM_SHA256 是最方便，也最快速的，因为 AES_128_CCM 其实就是数据用 AES-CTR 进行加密。然后用 AES-CBC 模式对原文进行加密，然后取最后的一个加密过后的块，作为 MAC。由于 CBC 是串行的，所以每一位都会对最后的块产生影响。但是由于 OpenSSL 中默认不开启 TLS_AES_128_CCM_SHA256，所以即使我们实现了 TLS_AES_128_CCM_SHA256，但是由于服务器不支持，我们也无法做到与服务器正常通信。

![Untitled](images/Untitled.png)

因此我们只能实现 TLS_AES_128_GCM_SHA256 或 TLS_AES_256_GCM_SHA384。由于 AES-128-CTR 和 AES-256-CTR 的性能差不多，因此我们实现 TLS_AES_256_GCM_SHA384 中的 AES_256_GCM 加密算法，其他的工作都可以交给 TLS 库来实现。

# AES-256-GCM 算法流程分析

参考   [https://blog.csdn.net/T0mato_/article/details/53160772](https://blog.csdn.net/T0mato_/article/details/53160772)

在计数器模式下，我们不再对密文进行加密，而是对一个逐次累加的计数器进行加密，用加密后的比特序列与明文分组进行 XOR得到密文。过程如下图：

![Untitled](images/Untitled%201.png)

计数器模式下，每次与明文分组进行XOR的比特序列是不同的，因此，计数器模式解决了ECB模式中，相同的明文会得到相同的密文的问题。CBC，CFB，OFB模式都能解决这个问题，但CTR的另两个优点是：1）支持加解密并行计算，可事先进行加解密准备；2）错误密文中的对应比特只会影响明文中的对应比特等优点。

但CTR仍然不能提供密文消息完整性校验的功能。如果我们使用 Hash 对密文进行加密，当篡改者截获原始的密文消息时，先篡改密文，而后计算篡改后的密文hash,，替换掉原始消息中的密文hash。这样，消息接收者仍然没有办法发现对源密文的篡改。因此想要校验消息的完整性，必须引入另一个概念：消息验证码。消息验证码是一种与秘钥相关的单项散列函数。

![Untitled](images/Untitled%202.png)

对应到上图中的消息认证码，GMAC就是利用伽罗华域(Galois Field，GF，有限域)乘法运算来计算消息的MAC值。假设秘钥长度为128bits, 当密文大于128bits时，需要将密文按128bits进行分组。应用流程如下图：

![Untitled](images/Untitled%203.png)

GCM中的G就是指GMAC，C就是指CTR。 GCM可以提供对消息的加密和完整性校验，另外，它还可以提供附加消息的完整性校验。在实际应用场景中，有些信息是我们不需要保密，但信息的接收者需要确认它的真实性的，例如源IP，源端口，目的IP，IV，等等。因此，我们可以将这一部分作为附加消息加入到MAC值。

![Untitled](images/Untitled%204.png)

我们本次的实现，有很大程度上基于上面这张流程图。

# 具体实现

## 调用硬件加密 AES-CTR

Cryptodev-linux 让我们能访问 Linux 内核加密驱动程序。从而允许用户空间应用程序利用硬件加速器。

用 C 代码调用硬件，加速 AES-CTR。

```c
// 打开 /dev/crypto，这是 Cryptodev-linux 的用户态接口
	cfd = open("/dev/crypto", O_RDWR, 0);
	if (cfd < 0) {
		perror("open(/dev/crypto)");
		return 1;
	}

// 初始化加密 session，设置加密算法，key，key_size
	memset(ctx, 0, sizeof(*ctx));
	ctx->cfd = cfd;

	ctx->sess.cipher = CRYPTO_AES_CTR;
	ctx->sess.keylen = key_size;
	ctx->sess.key = (void*)key;
	if (ioctl(ctx->cfd, CIOCGSESSION, &ctx->sess)) { // 用 ioctl 向内核态传信息
		perror("ioctl(CIOCGSESSION)");
		return -1;
	}
	
// 原地加密，输入 plaintext, iv ，加密后的 ciphertext 直接把 plaintext 替换
	cryp.ses = ctx->sess.ses;
	cryp.len = size;
	cryp.src = (void*)plaintext;
	cryp.dst = ciphertext;
	cryp.iv = (void*)iv;
	cryp.op = COP_ENCRYPT;
	if (ioctl(ctx->cfd, CIOCCRYPT, &cryp)) {
		perror("ioctl(CIOCCRYPT)");
		return -1;
	}
	
// 原地解密，输入 ciphertext, iv ，解密后的 plaintext 直接把 ciphertext 替换
  cryp.ses = ctx->sess.ses;
	cryp.len = size;
	cryp.src = (void*)ciphertext;
	cryp.dst = plaintext;
	cryp.iv = (void*)iv;
	cryp.op = COP_DECRYPT;
	if (ioctl(ctx->cfd, CIOCCRYPT, &cryp)) {
		perror("ioctl(CIOCCRYPT)");
		return -1;
	}

```

## AES-256-GCM 具体实现

![Untitled](images/Untitled%204.png)

虽然 AES-256-GCM 流程图看起来比较简单，但是实现中还是有一些细节的，具体可以看下面的实现梳理和代码细节。

重要细节：

由于 TLS 中的 nonce 只有 12 字节，而 iv 长度为 16 字节，所以 iv 的前 12 字节为 nonce 的值，后面 4 个字节拿来当计数器。

```rust
# 下面的 nonce + x 代表前 12 字节为 nonce 的值，后面 4 个字节为 x 的值
AES-256-CTR(key,nonce,plaintext):
	ciphertext = AES-256-CTR(key,iv = nonce + 2,plaintext) # 计数器的值从 2 开始
	return ciphertext
	
	
GMAC(key,nonce,ciphertext,aad):
  h = AES-256(key, plaintext = 16 字节全 0 数组)
  gmac = Gmac::init(h); # 用 h 来当 gmac 的 key
  gmac.update(aad); # additional data，附加数据，不需要保密，
                     # 但信息的接收者需要确认它的真实性的信息，比如 IP
  gmac.update(ciphertext); # 加密后的内容 
  gmac.update(add.len() | ciphertext.len()); # [0..8] 为 附加数据长度
                                             # [8..16] 为 加密后数据长度
  code = gmac.finialize(); # gmac 完成了计算
  base_ectr = AES-256(key, plaintext = nonce + 1);
  
  # 最终的 MAC
  MAC = code xor base_ectr # 输出 mac 长度为 16 字节
  return MAC
  
AES-256-GCM-加密(key,nonce,plaintext):
	ciphertext = AES-256-CTR(key,nonce,plaintext)
	MAC = GMAC(key,nonce,ciphertext,aad)
	
	buffer = ciphertext + MAC # 把 MAC 直接放在密文后面
	return buffer

AES-256-GCM-解密(key,nonce,buffer):
	# 最后 16 字节为 mac
	ciphertext, mac = buffer[..buffer.len() - 16] , buffer[buffer.len() - 16..]
	plaintext = AES-256-CTR(key,nonce,ciphertext) # AES 对称加密算法
	MAC = GMAC(key,nonce,ciphertext,aad)
	
	# 如果 mac 不一致，说明信息被篡改
	if (MAC ！= mac)
		return NULL
	
	return plaintext
	

```

最核心的实现代码如下

```rust
impl<AesEnc: Aes, Gmac: GHash + Clone, Ctr: AesCtr> AesGcm<AesEnc, Gmac, Ctr> {
    pub fn new(key: &[u8]) -> Result<Self> {
        let aes = AesEnc::new(key);
        let ctr = Ctr::new(key)?;

        // compute h
        // GMAC 加密算法的 key 为用 AES 
        let mut h = [0u8; 16];
        aes.apply_in_place(&mut h);
        let ghash = Gmac::new(&h);

        Ok(Self { ghash, aes, ctr })
    }

    fn compute_gmac(&self, nonce: &[u8; 12], aad: &[u8], buffer: &[u8]) -> [u8; 16] {
        let mut ghash = self.ghash.clone();

        let mut octets = [0u8; 16];
        octets[0..8].copy_from_slice(&((aad.len() as u64) * 8).to_be_bytes());
        octets[8..16].copy_from_slice(&((buffer.len() as u64) * 8).to_be_bytes());

        ghash.update(aad);
        ghash.update(buffer);
        ghash.update(&octets);
        let code = ghash.finalize();

        let base_ectr = {
            let mut base_ectr = [0u8; 16];
            base_ectr[..12].copy_from_slice(nonce);
            base_ectr[15] = 1;

            self.aes.apply_in_place(&mut base_ectr);
            base_ectr
        };

        let mut gmac = [0u8; 16];
        for i in 0..16 {
            gmac[i] = code[i] ^ base_ectr[i];
        }

        gmac
    }

    pub fn encrypt_in_place(
        &self,
        nonce: &[u8; 12],
        aad: &[u8],
        buffer: &mut [u8],
    ) -> Result<[u8; 16]> {
        // ctr encrypt
        {
            let mut iv = [0u8; 16];
            iv[..12].copy_from_slice(nonce);
            iv[15] = 2;

            self.ctr.apply_in_place(&iv, buffer)?;
        }

        Ok(self.compute_gmac(nonce, aad, buffer))
    }

    pub fn decrypt_in_place(
        &self,
        nonce: &[u8; 12],
        aad: &[u8],
        buffer: &mut [u8],
        tag: &[u8; 16],
    ) -> Result<()> {
        if !constant_time_eq(&self.compute_gmac(nonce, aad, buffer), tag) {
            anyhow::bail!("invalid tag");
        }

        // ctr decrypt
        let mut iv = [0u8; 16];
        iv[..12].copy_from_slice(nonce);
        iv[15] = 2;

        self.ctr.apply_in_place(&iv, buffer)?;

        Ok(())
    }
}

```

## 让 TLS 1.3 调用我们自定义的 AES-256-GCM 实现

Rustls 库实现了自定义 crypto provider 的功能，可以很方便的替换掉它的 TLS 1.3 中的加密实现。

[https://github.com/rustls/rustls?tab=readme-ov-file#cryptography-providers](https://github.com/rustls/rustls?tab=readme-ov-file#cryptography-providers)

下面的代码就调用了我们自行实现的 Tls13Aes256Gcm AEAD 算法。

```rust
use rustls::crypto::ring::tls13::{AeadAlgorithm, Aes256GcmAead};
use crate::hwacc::Cipher;

pub static TLS13_AES_256_GCM_SHA384: SupportedCipherSuite =
    SupportedCipherSuite::Tls13(&rustls::Tls13CipherSuite {
        common: rustls::crypto::CipherSuiteCommon {
            suite: rustls::CipherSuite::TLS13_AES_256_GCM_SHA384,
            hash_provider: &hash::Sha384,
            confidentiality_limit: u64::MAX,
            integrity_limit: 1 << 36,
        },
        hkdf_provider: &rustls::crypto::tls13::HkdfUsingHmac(&hmac::Sha384Hmac),
        aead_alg: &aead::Tls13Aes256Gcm,
        quic: None,
    });

pub static CUSTOM: &[SupportedCipherSuite] = &[TLS13_AES_256_GCM_SHA384];

pub fn provider() -> rustls::crypto::CryptoProvider {
    rustls::crypto::CryptoProvider {
        cipher_suites: CUSTOM.to_vec(),
        ..rustls::crypto::ring::default_provider()
    }
}
```

只要在创建 tls 流中调用我们自行实现的 provider 函数即可

```rust
    let mut root_cert_store = rustls::RootCertStore::empty();
    root_cert_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let config = rustls::ClientConfig::builder_with_provider(provider().into())
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(root_cert_store)
        .with_no_client_auth();

    let connector = TlsConnector::from(Arc::new(config));
    let stream = TcpStream::connect(addr).await.unwrap();
```

具体的 Tls13CipherAes256Gcm 的实现如下，该实现调用我们自行实现的 TLS-256-GCM，然后把加解密后的结果封装为对应的 TLS 结构体：

```rust

impl cipher::MessageEncrypter for Tls13CipherAes256Gcm {
    fn encrypt(
        &mut self,
        m: cipher::BorrowedPlainMessage,
        seq: u64,
    ) -> Result<cipher::OpaqueMessage, rustls::Error> {
        let total_len = self.encrypted_payload_len(m.payload.len());

        // construct a TLSInnerPlaintext
        let mut payload = Vec::with_capacity(total_len);
        payload.extend_from_slice(m.payload);
        payload.push(m.typ.get_u8());

        let nonce = cipher::Nonce::new(&self.1, seq).0;
        let aad = cipher::make_tls13_aad(total_len);

        let tag = self
            .0
            .encrypt_in_place(&nonce, &aad, &mut payload)
            .map_err(|_| rustls::Error::EncryptError)?;
        payload.extend_from_slice(&tag);

        Ok(cipher::OpaqueMessage::new(
            ContentType::ApplicationData,
            ProtocolVersion::TLSv1_2,
            payload,
        ))
    }

    fn encrypted_payload_len(&self, payload_len: usize) -> usize {
        payload_len + 1 + AES256GCM_OVERHEAD
    }
}

impl cipher::MessageDecrypter for Tls13CipherAes256Gcm {
    fn decrypt(
        &mut self,
        mut m: cipher::OpaqueMessage,
        seq: u64,
    ) -> Result<cipher::PlainMessage, rustls::Error> {
        let payload = m.payload_mut();
        let nonce = cipher::Nonce::new(&self.1, seq).0;
        let aad = cipher::make_tls13_aad(payload.len());

        let tag = payload.split_off(payload.len() - 16);

        self.0
            .decrypt_in_place(&nonce, &aad, payload, &tag.try_into().unwrap())
            .map_err(|_| rustls::Error::DecryptError)?;

        m.into_tls13_unpadded_message()
    }
}

```

# 实验结果

没有硬件加速，进行本地环回测试，TLS 解密性能为：2.5MB/s

有硬件加速，进行本地环回测试，TLS 解密性能为：6MB/s

测试发现，目前硬件加速实现的 AES-256-GCM 的瓶颈在于 GMAC 的计算，AES-CTR 的计算耗时反而不高。

# 讨论

- 目前 gmac 的计算没有实现并行化，如果能实现并行化，将能更好地利用路由器上的4线程 CPU，同时能降低加解密延迟。

参考文献：[https://www.intel.com/content/www/us/en/content-details/783641/advanced-encryption-standard-galois-counter-mode-optimized-ghash-function-technology-guide.html](https://www.intel.com/content/www/us/en/content-details/783641/advanced-encryption-standard-galois-counter-mode-optimized-ghash-function-technology-guide.html)

![Untitled](images/Untitled%205.png)

- 目前的实现只是 demo，后续可以在此基础上实现更多功能，比如实现基于硬件加速的内网穿透，任何用到 TLS 的程序都可以从中获益。