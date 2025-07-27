# pcap-test

## Assignment
송수신되는 packet을 capture하여 중요 정보를 출력하는 C/C++ 기반 프로그램을 작성하라.

- Ethernet Header의 src mac / dst mac
- IP Header의 src ip / dst ip
- TCP Header의 src port / dst port
- Payload(Data)의 hexadecimal value(최대 20바이트까지만)


## Usage

```bash
$ sudo ip link add dum0 type dummy
$ sudo ifconfig dum0 up
thread 1 : $ sudo ./pcap-test dum0
thread 2 : $ sudo tcpreplay -i dum0 h4mg.pcap
```

## Vedio
[Youtube Link](https://youtu.be/WpXeyJShsVA)   

## 과제 수행 사진
<img width="2628" height="1429" alt="Image" src="https://github.com/user-attachments/assets/efe9af46-8516-4a67-a3fb-75bd4f6ed250" />
