import math
import time

class VigenereCipher:
    def ReadTextFromFile(self, fpath):
        with open(fpath, 'r') as f:
            text = f.read()
        text = "".join(filter(str.isalnum, text))
        return text

    def WriteTextToFile(self, fpath, text):
        with open(fpath, 'w') as f:
            f.write(text)

    def EnVigenere(self, key, plaintxt, isOutLower=True):
        txtLength = len(plaintxt)
        keyLenth = len(key)
        keyIdx = 0
        ciphertxt = ''
        for i in range(txtLength):
            ptchar = plaintxt[i]
            ptord = ord(ptchar.lower())-ord('a')
            keychar = key[keyIdx]
            keyord = ord(keychar.lower())-ord('a')
            if isOutLower is True:
                ciphertxt += chr((ptord+keyord)%26+97)
            else:
                ciphertxt += chr((ptord+keyord)%26+65)
            keyIdx = (keyIdx+1)%keyLenth
        return ciphertxt

    def FriedmanTest(self, ciphertext, keyRange):
        residual = {x:0.0 for x in keyRange}
        for klen in keyRange:
            average = 0.0
            for i in range(0, klen):
                charlist = [0 for k in range(0,26)]
                subgroup = ciphertext[i::klen].lower()
                clen = len(subgroup)
                charStat = 0
                for c in range(0,26):
                    charlist[c] = subgroup.count(chr(c+97))
                    charStat += charlist[c]*(charlist[c]-1)
                average += charStat/(clen*(clen-1))
            average /= klen
            residual[klen] = abs(0.067-average)
            print('klen: ',klen,' IC: ',average,' diff: ',residual[klen])
        residual = sorted(residual.items(), key = lambda kv:kv[1], reverse=False)
        print(residual)
        best_guess = residual[0][0]
        second_best_guess = residual[1][0]
        # print('best_guess: ',best_guess,'    second_best_guess:',second_best_guess)
        if best_guess % second_best_guess == 0:
            return second_best_guess
        return best_guess

    def FreqAnalysis(self, keylen, ciphertext):
        freqlist = [0.08167,0.01492,0.02782,0.04253,0.12702,0.0228,0.02015,0.06094,0.06966,0.00153,0.00772,0.04025,0.02406,0.06749,0.07507,0.01929,0.00095,0.05987,0.06327,0.09056,0.02758,0.00978,0.0236,0.0015,0.01974,0.00074]
        key = ''
        for i in range(0,keylen):
            substr = ciphertext[i::keylen]
            all_chi_squareds = [0] * 26
            for i in range(26):
                chi_squared_sum = 0.0
                sequence_offset = [chr(((ord(substr[j])-97-i)%26)+97) for j in range(len(substr))]
                v = [0] * 26
                for l in sequence_offset:
                    v[ord(l) - ord('a')] += 1
                for j in range(26):
                    v[j] *= (1.0/float(len(substr)))
                for j in range(26):
                    chi_squared_sum+=((v[j] - float(freqlist[j]))**2)/float(freqlist[j])
                all_chi_squareds[i] = chi_squared_sum
            shift = all_chi_squareds.index(min(all_chi_squareds))
            key += chr(shift+97)
        return key

    def DeVigenere(self, ciphertext, key):
        plaintext = ''
        textlen = len(ciphertext)
        kenlen = len(key)
        for i in range(textlen):
            plaintext += chr((ord(ciphertext[i]) - ord(key[i%kenlen])) % 26 + 97)
        return plaintext


if __name__ == '__main__':
    vc = VigenereCipher()
    # key = 'SJTUSEIEE'
    # vc.WriteTextToFile('ciphertext.txt', vc.EnVigenere(key,vc.ReadTextFromFile('plaintext.txt')))
    # ctex = vc.ReadTextFromFile('ciphertext.txt')
    ctex = vc.ReadTextFromFile('Ciphertext3.txt')
    keyRange = range(3,30)
    start_time = time.time_ns()
    keylen = vc.FriedmanTest(ctex, keyRange)
    key = vc.FreqAnalysis(keylen, ctex)
    print('key = ',key)
    ptex = vc.DeVigenere(ctex, key)
    end_time = time.time_ns()
    print('Time Consuming: ',(end_time-start_time)/(10**9),'s')
    vc.WriteTextToFile('Decrypt Text.txt', ptex)