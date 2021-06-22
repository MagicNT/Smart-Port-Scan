import re, subprocess, sys


######################################################


def exec_cmd(cmd, output=""):
    if "masscan" in cmd:
        s = "ALL"   
    elif "-sU" in cmd:
        s = "UDP"
    else:
        s = "TCP" 
    print("\n============================> [ {} ] [ {} ]\n".format(cmd[0].upper(), s))
    sp = subprocess.Popen(cmd, shell=False, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    while True:
        out = sp.stdout.read(1).decode("utf-8")
        if out == "" and sp.poll() != None:
            break
        if out != "":
            output += out
            sys.stdout.write(out)
            sys.stdout.flush()
    return output


######################################################


def scan():
    ar_tcp = []
    ar_udp = []
    ip = sys.argv[1]
    output = exec_cmd(["masscan", "-p1-65535,U:1-65535", "--rate", "500", "--wait", "0", "--interactive", ip])
    text = str(output)
    for x in text.splitlines():
        if "Discovered open" in x:
            m = re.search("open port (\d{1,8})/(udp|tcp)", x) 
            if m.group(2) == "tcp":
                ar_tcp.append(m.group(1))
            elif "udp" == "udp":
                ar_udp.append(m.group(1)) 
    if ar_tcp:
        tcp_ports = ",".join(ar_tcp)
        output = exec_cmd(["nmap", "-Pn", "-sV", "--script", "vuln, firewalk", "-p" + tcp_ports, ip])
    if ar_udp:
        udp_ports = ",".join(ar_udp)
        output = exec_cmd(["nmap", "-Pn", "-sV", "--script", "vuln, firewalk", "-sU", "-p" + udp_ports, ip])


######################################################


if __name__ == "__main__":
    scan()


######################################################


