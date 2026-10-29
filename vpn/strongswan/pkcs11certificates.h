/*
    SPDX-FileCopyrightText: 2026 Mickael Bourneuf <mickael.bourneuf@ameleo.fr>

    SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only OR LicenseRef-KDE-Accepted-GPL
*/

#ifndef PKCS11CERTIFICATES_H
#define PKCS11CERTIFICATES_H

#include <QByteArray>
#include <QDateTime>
#include <QList>
#include <QString>

/**
 * An X.509 certificate found on a PKCS#11 token, with the RFC 7512 URI
 * that designates it.
 */
struct Pkcs11Certificate {
    QString uri;
    QString tokenLabel;
    QString subjectCommonName;
    QString subject;
    QString issuerCommonName;
    QDateTime expiryDate;

    // Raw CK_TOKEN_INFO, CKA_LABEL and CKA_ID, used to match a stored URI
    QByteArray tokenInfo;
    QByteArray label;
    QByteArray id;

    bool matchesUri(const QString &pkcs11Uri) const;
};

/**
 * Lists the end-entity X.509 certificates on the tokens of the PKCS#11
 * modules registered with p11-kit. Trust policy modules are skipped.
 * Certificates are public objects: no session is logged in.
 */
QList<Pkcs11Certificate> listPkcs11Certificates();

#endif // PKCS11CERTIFICATES_H
