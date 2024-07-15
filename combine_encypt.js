import crypto from 'crypto';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const filePath = path.join(__dirname, 'question.txt');

function encrypt(text, key, iv) {
    const algorithm = 'aes-256-cbc';
    const cipher = crypto.createCipheriv(algorithm, key, iv);
    let encrypted = cipher.update(text, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    return encrypted;
}

function decrypt(encrypted, key, iv) {
    const algorithm = 'aes-256-cbc';
    const decipher = crypto.createDecipheriv(algorithm, key, iv);
    let decrypted = decipher.update(encrypted, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
}

const key = crypto.randomBytes(32); // IIT BOMBAY SECRET 223
const iv = crypto.randomBytes(16);

fs.readFile(filePath, 'utf8', (err, data) => {
    if (err) {
        console.error('Error reading file', err);
        return;
    }

    const lines = data.split('\n').filter(line => line.trim() !== '');

    const PROBLEM_STATEMENT = lines[0];
    const OPTION_1 = lines[1];
    const OPTION_2 = lines[2];
    const OPTION_3 = lines[3];
    const OPTION_4 = lines[4];

    const encryptedProblem = encrypt(PROBLEM_STATEMENT, key, iv);
    const encryptedOption1 = encrypt(OPTION_1, key, iv);
    const encryptedOption2 = encrypt(OPTION_2, key, iv);
    const encryptedOption3 = encrypt(OPTION_3, key, iv);
    const encryptedOption4 = encrypt(OPTION_4, key, iv);

    console.log('Encrypted Problem statement:', encryptedProblem);
    console.log('Encrypted Option 1:', encryptedOption1);
    console.log('Encrypted Option 2:', encryptedOption2);
    console.log('Encrypted Option 3:', encryptedOption3);
    console.log('Encrypted Option 4:', encryptedOption4);

    const decryptedProblem = decrypt(encryptedProblem, key, iv);
    const decryptedOption1 = decrypt(encryptedOption1, key, iv);
    const decryptedOption2 = decrypt(encryptedOption2, key, iv);
    const decryptedOption3 = decrypt(encryptedOption3, key, iv);
    const decryptedOption4 = decrypt(encryptedOption4, key, iv);

    console.log('Decrypted Problem statement:', decryptedProblem);
    console.log('Decrypted Option 1:', decryptedOption1);
    console.log('Decrypted Option 2:', decryptedOption2);
    console.log('Decrypted Option 3:', decryptedOption3);
    console.log('Decrypted Option 4:', decryptedOption4);
});
