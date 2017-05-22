package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"strings"
	"bytes"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/terminal"
)

func main() {
	var username string
	var password string
	var port int
	var connectTimeout int //todo http://stackoverflow.com/questions/31554196/ssh-connection-timeout#31566330
	var hostsFile string
	var outfile string
	var commands []string
	flag.StringVar(&username, "username", "", "The username to be used when connecting.")
	flag.StringVar(&password, "password", "", "The password to be used when connecting (not recommended unless the username and password are transient).")
	flag.IntVar(&port, "port", 22, "The port to be used when connecting.")
	flag.IntVar(&connectTimeout, "timeout", 2, "Timeout (in seconds) before giving up on an SSH connection.")
	flag.StringVar(&hostsFile, "file", "", "Location of the file containing the host list.")
	flag.StringVar(&outfile, "outfile", "", "Location of the file where the results will be saved.")

	flag.Parse()
	commands = flag.Args()
	if len(commands) < 1 {
		flag.PrintDefaults()
		os.Exit(1)
	}

	hosts := readHostsFrom(hostsFile)

	if password == "" {
		password = promptForPassword()
	}

	var outputs []string

	for _, host := range hosts {
		sshConfig := &ssh.ClientConfig{
			User: username,
			Auth: []ssh.AuthMethod{
				ssh.Password(password),
			},
			HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		}
		client := &SSHClient{
			Config: sshConfig,
			Host:   host,
			Port:   port,
		}
		for _, command := range commands {
			output := ExecuteCommand(command, client)
			cleanedUpOutput := strings.Replace(output, "\r\n", " ", -2)
			cleanedUpOutput = strings.Replace(cleanedUpOutput, "\n", " ", -2)
			line := host + "|" + command + "|" + cleanedUpOutput
			fmt.Fprintln(os.Stdout, line)
			outputs = append(outputs, line)
		}
	}

	if outfile != "" {
		combinedOutput := strings.Join(outputs, "\n")
		d1 := []byte(combinedOutput)
		err := ioutil.WriteFile(outfile, d1, 0644)
		check(err, "failed to store results")
	}

}

func promptForPassword() string {
	fmt.Print("Enter Password: ")
	bytePassword, err := terminal.ReadPassword(0)
	if err != nil {
		panic("failed to read password")
	}
	return string(bytePassword)
}

func check(e error, message string) {
	if e != nil {
		fmt.Fprintln(os.Stderr, message)
		panic(e)
	}
}

func readHostsFrom(hostsFile string) []string {
	content, err := ioutil.ReadFile(hostsFile)
	check(err, "Failed to load host file")
	rawHostLines := strings.Split(string(content), "\n")
	var hosts []string
	for _, str := range rawHostLines {
		if str != "" {
			hosts = append(hosts, str)
		}
	}
	return hosts
}

func ExecuteCommand(command string, client *SSHClient) string {
	var b bytes.Buffer
	cmd := &SSHCommand{
		Path:   command,
		Env:    []string{"LC_DIR=/"},
		Stdin:  os.Stdin,
		Stdout: &b,
		Stderr: os.Stderr,
	}
	if err := client.RunCommand(cmd); err != nil {
		fmt.Fprintf(os.Stderr, "command run error: %s\n", err)
		os.Exit(1)
	}
	output := b.String()
	return output
}
