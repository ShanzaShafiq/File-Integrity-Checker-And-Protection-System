
//   FILE INTEGRITY CHECKER AND PROTECTION SYSTEM
//   Subject      : Information Security
//   Student      : Shanza Shafiq
//   Roll No      : BITF24M008
//   Submitted to : Sir Huzaifa Nazir

#include <iostream>
#include <fstream>
#include <string>
#include <ctime>
#include <conio.h>
using namespace std;

// files
const string DB_FILE = "hash.txt";
const string LOG_FILE = "log.txt";
const string PASSWORD = "shanza@00";
// Sha-256 implementation
string byteToHex(unsigned char b)
{
    const char hex[] = "0123456789abcdef";
    string result = "  ";
    result[0] = hex[b >> 4];
    result[1] = hex[b & 0x0F];
    return result;
}

//  SHA-256 CONSTANTS
static const unsigned int K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};

// Rotate right
unsigned int rotr(unsigned int x, unsigned int n)
{
    unsigned int right = x >> n;
    unsigned int left = x << (32 - n);

    unsigned int result = right | left;

    return result;
}
//  SHA-256 MAIN FUNCTION
string computeSHA256(const char *data, long size)
{
    // Starting hash values
    unsigned int h0 = 0x6a09e667, h1 = 0xbb67ae85;
    unsigned int h2 = 0x3c6ef372, h3 = 0xa54ff53a;
    unsigned int h4 = 0x510e527f, h5 = 0x9b05688c;
    unsigned int h6 = 0x1f83d9ab, h7 = 0x5be0cd19;

    // Padding
    unsigned long long bits = (unsigned long long)size * 8;
    long padded = size + 1;
    while (padded % 64 != 56)
    {
        padded++;
    }
    padded += 8;

    unsigned char *msg = new unsigned char[padded];
    for (long i = 0; i < size; i++)
    {
        msg[i] = (unsigned char)data[i];
    }
    msg[size] = 0x80;
    for (long i = size + 1; i < padded - 8; i++)
    {
        msg[i] = 0x00;
    }

    for (int i = 7; i >= 0; i--)
    {
        msg[padded - 8 + (7 - i)] = (unsigned char)((bits >> (i * 8)) & 0xFF);
    }
    // Process blocks
    for (long blk = 0; blk < padded; blk += 64)
    {
        unsigned int W[64];
        for (int i = 0; i < 16; i++)
            W[i] = ((unsigned int)msg[blk + i * 4] << 24) |
                   ((unsigned int)msg[blk + i * 4 + 1] << 16) |
                   ((unsigned int)msg[blk + i * 4 + 2] << 8) |
                   ((unsigned int)msg[blk + i * 4 + 3]);

        for (int i = 16; i < 64; i++)
        {
            unsigned int s0 = rotr(W[i - 15], 7) ^ rotr(W[i - 15], 18) ^ (W[i - 15] >> 3);
            unsigned int s1 = rotr(W[i - 2], 17) ^ rotr(W[i - 2], 19) ^ (W[i - 2] >> 10);
            W[i] = W[i - 16] + s0 + W[i - 7] + s1;
        }

        unsigned int a = h0, b = h1, c = h2, d = h3, e = h4, f = h5, g = h6, hh = h7;
        for (int i = 0; i < 64; i++)
        {
            unsigned int S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
            unsigned int ch = (e & f) ^ (~e & g);
            unsigned int t1 = hh + S1 + ch + K[i] + W[i];
            unsigned int S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
            unsigned int maj = (a & b) ^ (a & c) ^ (b & c);
            unsigned int t2 = S0 + maj;
            hh = g;
            g = f;
            f = e;
            e = d + t1;
            d = c;
            c = b;
            b = a;
            a = t1 + t2;
        }
        h0 += a;
        h1 += b;
        h2 += c;
        h3 += d;
        h4 += e;
        h5 += f;
        h6 += g;
        h7 += hh;
    }
    delete[] msg;

    // Convert to hex string
    unsigned int parts[8] = {h0, h1, h2, h3, h4, h5, h6, h7};
    string hash = "";
    for (int i = 0; i < 8; i++)
    {
        hash += byteToHex((parts[i] >> 24) & 0xFF);
        hash += byteToHex((parts[i] >> 16) & 0xFF);
        hash += byteToHex((parts[i] >> 8) & 0xFF);
        hash += byteToHex((parts[i]) & 0xFF);
    }
    return hash;
}

// read file
bool readFile(string path, char *&buffer, long &size)
{

    FILE *f = fopen(path.c_str(), "rb");
    if (f == nullptr)
    {
        cout << " File not found: " << path << "\n";
        return false;
    }

    fseek(f, 0, SEEK_END);
    size = ftell(f);
    fseek(f, 0, SEEK_SET);

    if (size == 0)
    {
        buffer = new char[1];
        buffer[0] = '\0';
        fclose(f);
        return true;
    }

    buffer = new char[size];
    fread(buffer, 1, size, f);
    fclose(f);
    return true;
}

//  HASH FIL
string hashFile(string path, bool &ok)
{
    char *buffer = nullptr;
    long size = 0;

    ok = readFile(path, buffer, size);
    if (!ok)
        return "";

    string hash = computeSHA256(buffer, size);
    delete[] buffer;
    return hash;
}
void writeLog(string msg)
{
    ofstream log(LOG_FILE, ios::app);

    time_t now = time(0);
    string timeStr = ctime(&now);
    if (!timeStr.empty() && timeStr[timeStr.size() - 1] == '\n')
        timeStr.erase(timeStr.size() - 1);

    log << "[" << timeStr << "] : " << msg << "\n";
    log.close();
}
//  ADD FILE
void addFile(string path)
{
    while (!path.empty() && (path[0] == ' ' || path[0] == '\r' || path[0] == '\n'))
        path.erase(0, 1);
    while (!path.empty() && (path[path.size() - 1] == ' ' || path[path.size() - 1] == '\r' || path[path.size() - 1] == '\n'))
        path.erase(path.size() - 1);

    bool ok;
    string hash = hashFile(path, ok);
    if (!ok)
        return;
    ifstream check(DB_FILE);
    string p, h;
    bool exists = false;

    while (getline(check, p, '|') && getline(check, h))
    {
        if (p == path)
        {
            exists = true;
            break;
        }
    }
    check.close();

    if (exists)
    {
        cout << "  File already monitored!\n";
        return;
    }

    ofstream db(DB_FILE, ios::app);
    db << path << "|" << hash << "\n";
    db.close();

    cout << " File Added!\n";
    cout << "  Hash: " << hash << "\n";
    writeLog("File Added: " + path);
}

void checkFile(string path)
{
    while (!path.empty() && (path[0] == ' ' || path[0] == '\r' || path[0] == '\n'))
        path.erase(0, 1);
    while (!path.empty() && (path[path.size() - 1] == ' ' || path[path.size() - 1] == '\r' || path[path.size() - 1] == '\n'))
        path.erase(path.size() - 1);
    ifstream db(DB_FILE);
    string p, oldHash;
    bool found = false;

    while (getline(db, p, '|') && getline(db, oldHash))
    {
        if (p == path)
        {
            found = true;
            break;
        }
    }
    db.close();

    while (!oldHash.empty() && (oldHash[oldHash.size() - 1] == ' ' || oldHash[oldHash.size() - 1] == '\r' || oldHash[oldHash.size() - 1] == '\n'))
        oldHash.erase(oldHash.size() - 1);

    if (!found)
    {
        cout << "  File not in database!\n";
        cout << "  Add it first using Option 1.\n";
        return;
    }

    bool ok;
    string newHash = hashFile(path, ok);

    if (!ok)
    {
        cout << "File is MISSING!\n";
        writeLog("File Missing: " + path);
        return;
    }

    cout << "\n  Old Hash : " << oldHash << "\n";
    cout << "  New Hash : " << newHash << "\n\n";

    if (oldHash == newHash)
    {

        cout << "  |  STATUS: FILE IS SAFE ..........\n";
        cout << "  |  Hashes match. No changes found....   |\n";

        writeLog("SAFE: " + path);
    }
    else
    {
        cout << " ALERT: FILE HAS BEEN MODIFIED!     \n";
        cout << "   Hashes do NOT match!               \n";

        writeLog("MODIFIED: " + path);
    }
}

void viewAllFiles()
{
    ifstream db(DB_FILE);

    if (!db.is_open())
    {
        cout << "  No files monitored yet.\n";
        return;
    }

    cout << "\n MONITORED FILES \n\n";
    string p, h;
    int count = 0;

    while (getline(db, p, '|') && getline(db, h))
    {
        count++;
        cout << "  [" << count << "] " << p << "\n";
        cout << "      Hash: " << h << "\n\n";
    }
    db.close();

    if (count == 0)
        cout << "  Database is empty.\n";
    else
        cout << "  Total: " << count << " file(s)\n";
}

void viewLog()
{
    ifstream log(LOG_FILE);

    if (!log.is_open())
    {
        cout << "  Log is empty.\n";
        return;
    }

    cout << "\n  ACTIVITY LOG \n\n";
    string line;
    while (getline(log, line))
        cout << "  " << line << "\n";

    log.close();
}

bool login()
{
    system("cls");
    cout << "\n\n";
    ;
    cout << "    FILE INTEGRITY CHECKER AND PROTECTION SYSTEM             \n";
    ;

    int attempts = 0;

    while (attempts < 3)
    {
        cout << "   Enter Password: ";

        string password = "";
        char ch;

        while ((ch = _getch()) != '\r')
        {
            if (ch == '\b' && !password.empty())
            {
                password.erase(password.size() - 1);
                cout << "\b \b";
            }
            else if (ch != '\b')
            {
                password += ch;
                cout << '*';
            }
        }
        cout << "\n";

        if (password == PASSWORD)
        {
            cout << "\n   Welcome!\n\n";
            writeLog("Login Successful");
            return true;
        }

        attempts++;
        int left = 3 - attempts;
        cout << "Wrong password!";
        if (left > 0)
            cout << " " << left << " attempt(s) left.\n\n";
        else
            cout << "\n";

        writeLog("Failed login attempt " + to_string(attempts));
    }

    cout << "\n System locked!\n\n";
    writeLog("System Locked  too many failed attempts");
    return false;
}
int main()
{
    if (!login())
    {
        cout << "   Press Enter to exit...";
        cin.get();
        return 0;
    }

    int choice = 0;
    string path;

    while (choice != 5)
    {

        cout << "   1. Add File\n";
        cout << "   2. Check File\n";
        cout << "   3. View All Files\n";
        cout << "   4. View Log\n";
        cout << "   5. Exit\n";
        cout << "   Choice: ";
        cin >> choice;
        cin.ignore();

        if (choice == 1)
        {
            cout << "   File path: ";
            getline(cin, path);
            addFile(path);
        }
        else if (choice == 2)
        {
            cout << "   File path: ";
            getline(cin, path);
            checkFile(path);
        }
        else if (choice == 3)
        {
            viewAllFiles();
        }
        else if (choice == 4)
        {
            viewLog();
        }
        else if (choice != 5)
        {
            cout << "   Invalid choice! Enter 1-5.\n";
        }
    }

    cout << "\n   Goodbye! Stay secure.\n\n";
    writeLog("User logged out");
    return 0;
}
