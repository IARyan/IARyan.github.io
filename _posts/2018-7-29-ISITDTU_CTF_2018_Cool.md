---

layout: post

title: ISITDTU CTF 2018 Cool Writeup
---

I started this challenge by running the binary to see what it prints on stdout and what it is expecting on stdin.

| Executing Cool Binary |
|---|
|![Execute Binary](/images/ISITDTU/cool/cool_run.png)|

The challenge looked like a standard reverse engineering challenge that takes some user input then determines if its correct by checking the input against something in the binary. After reviewing the logic of the binary in IDA Pro, I determined that it performs four total checks:
  1.	Checks that the input string is 28 characters long.
  2.	Checks the first 12 characters against saved md5 hashes 4 characters at a time.
  3.	Checks the 13th character is 0x21 (‘!’ in ascii).
  4.	Checks the remaining characters feedback xor byte against an array of known feedback xor bytes.

Passing the first check was very easy, one just needs to make sure the input string is 28 characters. The second check can be passed using google to get the string that generates the saved md5 hashes.

| Length and MD5 Checks in IDA Pro |
|---|
|![Length and MD5 Checks in IDA Pro](/images/ISITDTU/cool/cool_strlen_md5.png)|

| MD5 Cracked Strings |
|---|
|![MD5 Cracked Strings](/images/ISITDTU/cool/cool_hashes.png)|

The third check is passed by adding a ‘!’ to the current input string. Making the first 13 characters of the input string: “fl4g_i5_h3r3!”. 

| "!" Check in IDA Pro |
|---|
|!["!" Check in IDA Pro](/images/ISITDTU/cool/cool_13_char.png)|

To pass the fourth check some reversing was required. After looking at the binary in IDA Pro it was determined that a running feedback xor byte is used to verify if the input string is correct. The first 13 characters are xor against the previous xor output byte to produce one a single running check byte. The final 15 characters are xor against the running check byte then checked against an array of known feedback xor bytes to verify the solution is correct. Python source code that emulates this process can be found below:
```python
def find_solution():
  """
  Finds the solution string to pass to the challenge binary.
  """
  # Running xor byte used to check solution
  xor_byte = 0

  # Solution byte array pulled from address 0x6020A8 in the binary
  solution_check_bytes = "7D4D2344360276036F5B2F46761839".decode("hex")

  # Construct the first 13 chars of the solution to pass the first checks in binary
  #ecfd4245812b86ab2a878ca8cb1200f9 = "fl4g"  (0x400DDD)
  #88e3e2edb64d39698a2cc0a08588b5fd = "_i5_"  (0x400E1B)
  #bbc86f9d0b90b9b08d1256b4ef76354b = "h3r3"  (0x400E59)
  solution = "fl4g_i5_h3r3!"

  # Calculate the running xor byte for the first part of the solution
  for i in range(len(solution)):
    xor_byte ^= ord(solution[i])
    
  # Brute force the second part of the solution by using the solution byte array
  # to check the running xor byte against
  for solution_check_byte in solution_check_bytes:
    for char in string.printable:
      if chr(xor_byte ^ ord(char)) == solution_check_byte:
        solution += char
        xor_byte ^= ord(char)

  # Return the solution string
  return solution
```
After running the binary against the solution code, the flag was determined and submitted to score 100 points.

| Flag |
|---|
|![Flag](/images/ISITDTU/cool/cool_flag.png)|

Challenge binary and solution script can be found here: [https://github.com/IARyan/CTFSolutions/tree/master/2018/ISITDTU](https://github.com/IARyan/CTFSolutions/tree/master/2018/ISITDTU)
