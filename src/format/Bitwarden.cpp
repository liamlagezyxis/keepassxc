/*
 *  Copyright (C) 2023 KeePassXC Team <team@keepassxc.org>
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 2 or (at your option)
 *  version 3 of the License.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "Bitwarden.h"

#include "core/Database.h"
#include "core/Entry.h"
#include "core/Group.h"
#include "core/Metadata.h"
#include "totp/totp.h"

#include <QFileInfo>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QMap>
#include <QScopedPointer>
#include <QUrl>

namespace
{
    Entry* readItem(const QJsonObject& item, QString& folderId)
    {
        // Create the item map and extract the folder id
        auto itemMap = item.toVariantMap();
        folderId = itemMap.value("folderId").toString();

        // Create entry and assign basic values
        QScopedPointer<Entry> entry(new Entry());
        entry->setUuid(QUuid::createUuid());
        entry->setTitle(itemMap.value("name").toString());
        entry->setNotes(itemMap.value("notes").toString());

        if (itemMap.value("favorite").toBool()) {
            entry->addTag(QObject::tr("Favorite", "Tag for favorite entries"));
        }

        // Parse login details if present
        if (itemMap.contains("login")) {
            auto loginMap = itemMap.value("login").toMap();
            entry->setUsername(loginMap.value("username").toString());
            entry->setPassword(loginMap.value("password").toString());
            if (loginMap.contains("totp")) {
                // Bitwarden stores TOTP as otpauth string
                entry->setTotp(Totp::parseSettings(loginMap.value("totp").toString()));
            }

            // Set the entry url(s)
            int i = 1;
            for (const auto& urlObj : loginMap.value("uris").toList()) {
                auto url = urlObj.toJsonObject().value("uri").toString();
                if (entry->url().isEmpty()) {
                    entry->setUrl(url);
                } else {
                    entry->attributes()->set(QString("KP2A_URL_%1").arg(i), url);
                    ++i;
                }
            }
        }

        // Parse identity details if present
        if (itemMap.contains("identity")) {
            /*
                "title": "Mrs",
                "firstName": "Jane",
                "middleName": "A",
                "lastName": "Doe",
                "address1": " 1 North Calle Cesar Chavez ",
                "address2": null,
                "address3": null,
                "city": "Santa Barbara",
                "state": "CA",
                "postalCode": "93103",
                "country": "United States ",
                "company": "My Employer",
                "email": "myemail@gmail.com",
                "phone": "123-123-1234",
                "ssn": "123-12-1234",
                "username": "myusername",
                "passportNumber": "123456789",
                "licenseNumber": "123456789"
             */
            auto idMap = itemMap.value("identity").toMap();
            // Combine all the address attributes into a fully formed structure
            auto address = idMap.value("address1").toString() + "\n" + idMap.value("city").toString() + ", "
                    + idMap.value("state").toString() + " " + idMap.value("postalcode").toString() + "\n"
                    + idMap.value("country").toString();
            entry->attributes()->set("identity_address", address);
        }

        // Parse card details if present
        if (itemMap.contains("card")) {
            /*
                "cardholderName": "Jane Doe",
                "brand": "Visa",
                "number": "1234567891011121",
                "expMonth": "10",
                "expYear": "2021",
                "code": "123"
             */
        }

        // Parse fields
        for (const auto& field : itemMap.value("fields").toList()) {
            // Derive a prefix for attribute names using the title or uuid if missing
            auto fieldMap = field.toMap();
            auto name = fieldMap.value("name").toString();
            if (entry->attributes()->hasKey(name)) {
                name = QString("%1_%2").arg(name, QUuid::createUuid().toString().mid(1, 5));
            }

            auto value = fieldMap.value("value").toString();
            int type = fieldMap.value("type").toInt();

            entry->attributes()->set(name, value, type  == 1);
        }

        // Collapse any accumulated history
        entry->removeHistoryItems(entry->historyItems());

        // Adjust the created and modified times
        auto timeInfo = entry->timeInfo();
        auto createdTime = QDateTime::fromSecsSinceEpoch(itemMap.value("createdAt").toULongLong(), Qt::UTC);
        auto modifiedTime = QDateTime::fromSecsSinceEpoch(itemMap.value("updatedAt").toULongLong(), Qt::UTC);
        timeInfo.setCreationTime(createdTime);
        timeInfo.setLastModificationTime(modifiedTime);
        timeInfo.setLastAccessTime(modifiedTime);
        entry->setTimeInfo(timeInfo);

        return entry.take();
    }

    void writeVaultToDatabase(const QJsonObject& vault, QSharedPointer<Database> db)
    {
        if (!vault.contains("folders") || !vault.contains("items")) {
            // Early out if the vault is missing critical items
            return;
        }

        // Create groups from folders and store a temporary map of id -> uuid
        QMap<QString, Group*> folderMap;
        for (auto folder : vault.value("folders").toArray()) {
            auto group = new Group();
            group->setUuid(QUuid::createUuid());
            group->setName(folder.toObject().value("name").toString());
            group->setParent(db->rootGroup());

            folderMap.insert(folder.toObject().value("id").toString(), group);
        }

        QString folderId;
        const auto items = vault.value("items").toArray();
        for (const auto& item : items) {
            auto entry = readItem(item.toObject(), folderId);
            if (entry) {
                entry->setGroup(folderMap.value(folderId, db->rootGroup()), false);
            }
        }
    }
} // namespace

bool BitwardenReader::hasError()
{
    return !m_error.isEmpty();
}

QString BitwardenReader::errorString()
{
    return m_error;
}

QSharedPointer<Database> BitwardenReader::convert(const QString& path)
{
    m_error.clear();

    QFileInfo fileinfo(path);
    if (!fileinfo.exists()) {
        m_error = QObject::tr("File does not exist.").arg(path);
        return {};
    }

    // Bitwarden uses a json file format
    QFile file(fileinfo.absoluteFilePath());
    if (!file.open(QFile::ReadOnly)) {
        m_error = QObject::tr("Cannot open file: %1").arg(file.errorString());
        return {};
    }

    auto db = QSharedPointer<Database>::create();
    const auto json = QJsonDocument::fromJson(file.readAll());
    file.close();
    
    writeVaultToDatabase(json.object(), db);
    
    return db;
}
