define($IP 192.168.56.105)
define($MAC 00:00:00:00:01:00)

source :: FromDevice
dest :: ToDevice

c :: Classifier(
  23/06,           //This is to match TCP SYN packets
  -);                //Default case

source -> c

c[0] -> Strip(26) -> Print('TCP Packet', 0) -> TCounter -> EtherMirror -> dest;

c[1] -> Print('OTHERS',0)  -> Discard;


