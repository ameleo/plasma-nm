/*
    SPDX-FileCopyrightText: 2026 Mickael Bourneuf <mickael.bourneuf@ameleo.fr>

    SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only OR LicenseRef-KDE-Accepted-GPL
*/

#include "pkcs11certificates.h"

#include <QSslCertificate>
#include <QSslCertificateExtension>

#include <p11-kit/p11-kit.h>
#include <p11-kit/uri.h>

#include <algorithm>
#include <cstdlib>
#include <cstring>
#include <vector>

namespace
{
QByteArray attributeValue(CK_FUNCTION_LIST *module, CK_SESSION_HANDLE session, CK_OBJECT_HANDLE object, CK_ATTRIBUTE_TYPE type)
{
    CK_ATTRIBUTE attribute = {type, nullptr, 0};
    if (module->C_GetAttributeValue(session, object, &attribute, 1) != CKR_OK || attribute.ulValueLen == CK_UNAVAILABLE_INFORMATION) {
        return {};
    }
    QByteArray value(static_cast<qsizetype>(attribute.ulValueLen), Qt::Uninitialized);
    attribute.pValue = value.data();
    if (module->C_GetAttributeValue(session, object, &attribute, 1) != CKR_OK) {
        return {};
    }
    return value;
}

bool isCertificateAuthority(const QSslCertificate &certificate)
{
    const QList<QSslCertificateExtension> extensions = certificate.extensions();
    for (const QSslCertificateExtension &extension : extensions) {
        if (extension.name() == QLatin1String("basicConstraints")) {
            return extension.value().toMap().value(QStringLiteral("ca")).toBool();
        }
    }
    return false;
}

// RFC 7512 URI made of the token label, the object label and, when asked, the object id
QString formatUri(const CK_TOKEN_INFO &token, QByteArray label, QByteArray id, bool withId)
{
    P11KitUri *uri = p11_kit_uri_new();
    if (p11_kit_space_strlen(token.label, sizeof(token.label)) > 0) {
        std::memcpy(p11_kit_uri_get_token_info(uri)->label, token.label, sizeof(token.label));
    }
    CK_OBJECT_CLASS objectClass = CKO_CERTIFICATE;
    CK_ATTRIBUTE classAttribute = {CKA_CLASS, &objectClass, sizeof(objectClass)};
    p11_kit_uri_set_attribute(uri, &classAttribute);
    if (!label.isEmpty()) {
        CK_ATTRIBUTE labelAttribute = {CKA_LABEL, label.data(), static_cast<CK_ULONG>(label.size())};
        p11_kit_uri_set_attribute(uri, &labelAttribute);
    }
    if (withId && !id.isEmpty()) {
        CK_ATTRIBUTE idAttribute = {CKA_ID, id.data(), static_cast<CK_ULONG>(id.size())};
        p11_kit_uri_set_attribute(uri, &idAttribute);
    }

    QString result;
    char *string = nullptr;
    if (p11_kit_uri_format(uri, P11_KIT_URI_FOR_OBJECT_ON_TOKEN, &string) == P11_KIT_URI_OK) {
        result = QString::fromUtf8(string);
        std::free(string);
    }
    p11_kit_uri_free(uri);
    return result;
}

QList<Pkcs11Certificate> tokenCertificates(CK_FUNCTION_LIST *module, CK_SESSION_HANDLE session, const CK_TOKEN_INFO &token)
{
    CK_OBJECT_CLASS objectClass = CKO_CERTIFICATE;
    CK_CERTIFICATE_TYPE certificateType = CKC_X_509;
    CK_ATTRIBUTE pattern[] = {
        {CKA_CLASS, &objectClass, sizeof(objectClass)},
        {CKA_CERTIFICATE_TYPE, &certificateType, sizeof(certificateType)},
    };
    if (module->C_FindObjectsInit(session, pattern, 2) != CKR_OK) {
        return {};
    }
    std::vector<CK_OBJECT_HANDLE> objects;
    CK_OBJECT_HANDLE batch[32];
    CK_ULONG found = 0;
    while (module->C_FindObjects(session, batch, 32, &found) == CKR_OK && found > 0) {
        objects.insert(objects.end(), batch, batch + found);
    }
    module->C_FindObjectsFinal(session);

    const QString tokenLabel = QString::fromUtf8(reinterpret_cast<const char *>(token.label), p11_kit_space_strlen(token.label, sizeof(token.label)));
    QList<Pkcs11Certificate> certificates;
    for (CK_OBJECT_HANDLE object : objects) {
        const QSslCertificate x509(attributeValue(module, session, object, CKA_VALUE), QSsl::Der);
        if (x509.isNull() || isCertificateAuthority(x509)) {
            continue;
        }
        Pkcs11Certificate certificate;
        certificate.tokenLabel = tokenLabel;
        certificate.subjectCommonName = x509.subjectInfo(QSslCertificate::CommonName).join(QLatin1String(", "));
        certificate.subject = x509.subjectDisplayName();
        certificate.issuerCommonName = x509.issuerInfo(QSslCertificate::CommonName).join(QLatin1String(", "));
        if (certificate.issuerCommonName.isEmpty()) {
            certificate.issuerCommonName = x509.issuerDisplayName();
        }
        certificate.expiryDate = x509.expiryDate();
        certificate.tokenInfo = QByteArray(reinterpret_cast<const char *>(&token), sizeof(token));
        certificate.label = attributeValue(module, session, object, CKA_LABEL);
        certificate.id = attributeValue(module, session, object, CKA_ID);
        certificates.append(certificate);
    }

    // The label survives a rekey, the id does not: the id is added only when the label is missing or ambiguous
    for (Pkcs11Certificate &certificate : certificates) {
        const bool ambiguous = std::count_if(certificates.cbegin(), certificates.cend(), [&certificate](const Pkcs11Certificate &other) {
                                   return other.label == certificate.label;
                               })
            > 1;
        certificate.uri = formatUri(token, certificate.label, certificate.id, certificate.label.isEmpty() || ambiguous);
    }
    return certificates;
}
}

bool Pkcs11Certificate::matchesUri(const QString &pkcs11Uri) const
{
    if (tokenInfo.size() != sizeof(CK_TOKEN_INFO)) {
        return false;
    }
    P11KitUri *uri = p11_kit_uri_new();
    bool match = false;
    if (p11_kit_uri_parse(pkcs11Uri.toUtf8().constData(), P11_KIT_URI_FOR_OBJECT_ON_TOKEN, uri) == P11_KIT_URI_OK) {
        CK_OBJECT_CLASS objectClass = CKO_CERTIFICATE;
        QByteArray objectLabel = label;
        QByteArray objectId = id;
        CK_ATTRIBUTE attributes[] = {
            {CKA_CLASS, &objectClass, sizeof(objectClass)},
            {CKA_LABEL, objectLabel.data(), static_cast<CK_ULONG>(objectLabel.size())},
            {CKA_ID, objectId.data(), static_cast<CK_ULONG>(objectId.size())},
        };
        CK_TOKEN_INFO token;
        std::memcpy(&token, tokenInfo.constData(), sizeof(token));
        match = p11_kit_uri_match_token_info(uri, &token) && p11_kit_uri_match_attributes(uri, attributes, 3);
    }
    p11_kit_uri_free(uri);
    return match;
}

QList<Pkcs11Certificate> listPkcs11Certificates()
{
    QList<Pkcs11Certificate> certificates;
    CK_FUNCTION_LIST **modules = p11_kit_modules_load_and_initialize(0);
    if (!modules) {
        return certificates;
    }
    for (CK_FUNCTION_LIST **entry = modules; *entry; ++entry) {
        CK_FUNCTION_LIST *module = *entry;
        // The system trust store holds authorities, not certificates to authenticate with
        if (p11_kit_module_get_flags(module) & P11_KIT_MODULE_TRUSTED) {
            continue;
        }
        CK_ULONG count = 0;
        if (module->C_GetSlotList(CK_TRUE, nullptr, &count) != CKR_OK || count == 0) {
            continue;
        }
        std::vector<CK_SLOT_ID> slotIds(count);
        if (module->C_GetSlotList(CK_TRUE, slotIds.data(), &count) != CKR_OK) {
            continue;
        }
        slotIds.resize(count);
        for (CK_SLOT_ID slot : slotIds) {
            CK_TOKEN_INFO token;
            CK_SESSION_HANDLE session;
            if (module->C_GetTokenInfo(slot, &token) != CKR_OK || module->C_OpenSession(slot, CKF_SERIAL_SESSION, nullptr, nullptr, &session) != CKR_OK) {
                continue;
            }
            certificates += tokenCertificates(module, session, token);
            module->C_CloseSession(session);
        }
    }
    p11_kit_modules_finalize_and_release(modules);

    std::sort(certificates.begin(), certificates.end(), [](const Pkcs11Certificate &a, const Pkcs11Certificate &b) {
        if (a.tokenLabel != b.tokenLabel) {
            return a.tokenLabel.localeAwareCompare(b.tokenLabel) < 0;
        }
        return a.subjectCommonName.localeAwareCompare(b.subjectCommonName) < 0;
    });
    return certificates;
}
