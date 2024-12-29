#include <QCryptographicHash>

#include "./qaesencryption.h"

int main()
{
    const QString encrypt_and_decrypt = "Name of the key used for encryption and decryption";

    {
        // Encrypt
        QString Plaintext  = "An example";
        QString Ciphertext = encrypt_algorithm(encrypt_and_decrypt, Plaintext);
    }

    {
        // Decrypt
        QByteArray data      = "An example";
        QString    Plaintext = decrypt_algorithm(encrypt_and_decrypt, data);
    }

    return 0;
}

QString encrypt_algorithm(const QString &keyword, const QString &Plaintext)
{
    // Encrypt
    QString        key_enctypt(keyword);
    QAESEncryption encryption(QAESEncryption::AES_128, QAESEncryption::ECB, QAESEncryption::ZERO);
    QByteArray     hashKey     = QCryptographicHash::hash(key_enctypt.toUtf8(), QCryptographicHash::Md5);
    QByteArray     encodedText = encryption.encode(Plaintext.toUtf8(), hashKey);
    QString        Ciphertext  = QString::fromLatin1(encodedText.toBase64());

    return Ciphertext;
}

QString decrypt_algorithm(const QString &keyword, const QByteArray &Ciphertext)
{
    // Decrypt
    QString        key_decrypt(keyword);
    QAESEncryption encryption(QAESEncryption::AES_128, QAESEncryption::ECB, QAESEncryption::ZERO);
    QByteArray     hashKey     = QCryptographicHash::hash(key_decrypt.toUtf8(), QCryptographicHash::Md5);
    QByteArray     decodedText = encryption.decode(QByteArray::fromBase64(Ciphertext), hashKey);
    QString        Plaintext   = QString::fromUtf8(decodedText).replace(QChar(0x00), "");

    return Plaintext;
}
