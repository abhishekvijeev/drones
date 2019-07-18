#((((((\0020\n|\n.)/home/abhishek/coding/c/createdir|\n[#]([^\0000])+)< 0x6>|(\0020|[])\t([^\0000])+< 0x8>)|(\0020|[])\t([^\0000])+< 0x10>)|(\0002|((\0020|[])\t/home/abhishek/coding/c/createdir|(\n|(\a|\t))))< 0x4>)|(\0020\n|\n.)unconfined< 0x4>)
#

data = raw_input()
s = ""
for i in data:
    if i == "(":
        continue
    elif i == ")":
        print (s)
        s = ""
    else:
        s = s + i

print (s)
