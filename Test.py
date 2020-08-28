from charm.core.math.integer import integer
from charm.toolbox.integergroup import IntegerGroupQ
from charm.toolbox.PKSig import PKSig
from charm.toolbox.pairinggroup import *
from charm.toolbox.pairinggroup import PairingGroup,ZR,G1,G2,GT,pair
from charm.toolbox.hash_module import Waters
from charm.toolbox.secretutil import SecretUtil
from charm.toolbox.ABEnc import ABEnc

class DSA(PKSig):
    def __init__(self, p=0, q=0):
        global group
        group = IntegerGroupQ()
        group.p, group.q, group.r = p, q, 2
    def keygen(self, bits):
        if group.p == 0 or group.q == 0:
            group.paramgen(bits)
        global p,q
        p,q = group.p, group.q 
        x = group.random()
        g = group.randomGen()
        y = (g ** x) % p
        return ({'g':g, 'y':y}, x)
    def sign(self, pk, x, M):
        while True:
            k = group.random()
            r = (pk['g'] ** k) % q
            s = (k ** -1) * ((group.hash(M) + x*r) % q)
            if (r == 0 or s == 0):
                print("unlikely error r = %s, s = %s" % (r,s))
                continue
            else:
                break
        return { 'r':r, 's':s }
    def verify(self, pk, sig, M):
        w = (sig['s'] ** -1) % q
        u1 = (group.hash(M) * w) % q
        u2 = (sig['r'] * w) % q
        v = ((pk['g'] ** u1) * (pk['y'] ** u2)) % p
        v %= q   
        if v == sig['r']:
            return True
        else:
            return False

def GSetup(g2,group2,groupZ):
    Alpha, Beta = groupZ.random(),groupZ.random();

    x2 = (g2**Alpha) % group2.n;
    y2 = (g2**Beta) % group2.n;
    gmsk = [Alpha,Beta]
    gpk = [x2,y2]
    return gmsk,gpk


def PKIJoin(security_parameter):
    #https://jhuisi.github.io/charm/charm/schemes/pksig/pksig_dsa.html
    p = integer(15)
    q = integer(7)  
    #p = integer(156053402631691285300957066846581395905893621007563090607988086498527791650834395958624527746916581251903190331297268907675919283232442999706619659475326192111220545726433895802392432934926242553363253333261282122117343404703514696108330984423475697798156574052962658373571332699002716083130212467463571362679)
    #q = integer(78026701315845642650478533423290697952946810503781545303994043249263895825417197979312263873458290625951595165648634453837959641616221499853309829737663096055610272863216947901196216467463121276681626666630641061058671702351757348054165492211737848899078287026481329186785666349501358041565106233731785681339)
    dsa = DSA(p, q)
    (public_key, secret_key) = dsa.keygen(security_parameter)
    # msg = "hello world test message!!!"
    # signature = dsa.sign(public_key, secret_key, msg)
    # dsa.verify(public_key, signature, msg)
    return secret_key,public_key;

#USK, UPK = PKIJoin(1024);

#print (USK);




def GJoin(g1,g2,group1,group2,groupZ,hash1,hash2,dsa):
    GMSK, GPK = GSetup(g2,group2,groupZ);
    USK, UPK = PKIJoin(1024);
    #step 1
    kappa = groupZ.random();
    #-------problem kappa 6 mod 11 integer.element, but no simple operations
    t = hash2.hash(str(kappa));

    #step 2
    #transfer t
    print('a')
    #step 3
    #limit or r will overflow
    taf = int(groupZ.random());
    print('a')
    s = (g1**taf) % group1.n
    # print(type(s));
    # print(type(group1.n));
    x2 = int(GPK[0]);
    print('a')
    # x2 int
    y2= int(GPK[1]);
    # y2 int

    r = (x2**taf) % group2.n
    print('a')
    # k = mapping(g1,r)<-------problem
    print('where1');
    msg=0000
 
    #step 6
    #step 7


#G1 not needed
p1=3;
q1=5;
r1=2;
n1=(p1-1)*(q1-1);
group1 = IntegerGroupQ();
group1.p, group1.q, group1.r, group1.n = p1, q1, r1, n1;
g1 = group1.randomGen();
print(type(g1));

#G2
p2=5;
q2=7;
r2=2;
n2=(p2-1)*(q2-1);
group2 = IntegerGroupQ();
group2.p, group2.q, group2.r, group2.n = p2, q2, r2, n2;
g2 = group2.randomGen();

# print(type(g1));

# print(pair(g1,g2));

#GZ
pz=7;
qz=11;
rz=2;
nz=(pz-1)*(qz-1);
groupZ = IntegerGroupQ();
groupZ.p, groupZ.q, groupZ.r, groupZ.n = pz, qz, rz, nz;

# p = integer(141660875619984104245410764464185421040193281776686085728248762539241852738181649330509191671665849071206347515263344232662465937366909502530516774705282764748558934610432918614104329009095808618770549804432868118610669336907161081169097403439689930233383598055540343198389409225338204714777812724565461351567)
# q = integer(70830437809992052122705382232092710520096640888343042864124381269620926369090824665254595835832924535603173757631672116331232968683454751265258387352641382374279467305216459307052164504547904309385274902216434059305334668453580540584548701719844965116691799027770171599194704612669102357388906362282730675783)
# chamHash = ChamHash_Adm05(p, q)
# (public_key, secret_key) = chamHash.paramgen()
# msg = "hello world this is the message"
# c = chamHash.hash(public_key, msg)
#c == chamHash.hash(public_key, msg, c[1], c[2])

groupH1 = PairingGroup("SS512")
hash1 = Waters(groupH1, length=8, bits=32)

groupH2 = PairingGroup("SS512")
hash2 = Waters(groupH2, length=7, bits=16)



p = integer(23)
q = integer(521)    
dsaSign = DSA(p, q)



GJoin(g1,g2,group1,group2,groupZ,hash1,hash2,dsaSign);


test=PairingGroup("SS512");
g1= test.random(G1);
g2= test.random(G2);
gt= pair(g1,g2);
alpha=test.random();

print(pair(g1**alpha,g2));
print(pair(g1,g2)**alpha);

print(type(pair(g1,g2))); #<-----problem pair(g1,g2) returns a pairing element
# def GJoin(): 
#   print();

# def GSign():
#   print();

# def GVerify():
#   print();

# GSetup();