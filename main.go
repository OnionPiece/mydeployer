package main

/*
 Refer:
   - https://fale.io/blog/2017/06/05/create-a-pki-in-golang/
   - https://github.com/moby/moby/blob/master/docs/api/v1.24.md
   - https://github.com/muka/redzilla/blob/2c7ef22bb9e9448712b63f341936b504e14edbbb/docker/images.go#L109-L154
   - https://github.com/cpjudge/sandbox/blob/c9426cc952fd1731811d0b64a5a48fc9a59cefbf/test/main.go#L61-L93
   - https://community.atlassian.com/t5/Bitbucket-questions/git-error-Issuer-certificate-is-invalid/qaq-p/149388
   - https://www.cyberciti.biz/faq/how-to-curl-ignore-ssl-certificate-warnings-command-option/

 Etcd cluster refer:
   - https://coreos.com/etcd/docs/latest/v2/docker_guide.html
   - https://coreos.com/etcd/docs/latest/op-guide/container.html
   - https://github.com/kelseyhightower/etcd-production-setup
   - https://docs.docker.com/engine/reference/run/#cpu-period-constraint
   - https://www.kernel.org/doc/Documentation/scheduler/sched-bwc.txt
*/

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"github.com/docker/docker/api/types"
	containertypes "github.com/docker/docker/api/types/container"
	filterstypes "github.com/docker/docker/api/types/filters"
	mounttypes "github.com/docker/docker/api/types/mount"
	networktypes "github.com/docker/docker/api/types/network"
	"github.com/docker/docker/client"
	"github.com/docker/docker/pkg/archive"
	"gopkg.in/yaml.v2"
	"io/ioutil"
	"math/big"
	"net"
	"os"
	"os/exec"
	"path"
	"strings"
	"time"
)

type BuildImageLog struct {
	Stream      string `json:"stream,omitempty"`
	ErrorDetail string `json:"errorDetail,omitempty"`
}

type BuildImageInfo struct {
	Name   string `yaml:"name"`
	Source string `yaml:"source"`
}

type ImageBuild struct {
	Images     []BuildImageInfo  `yaml:"images"`
	ExtraHosts map[string]string `yaml:"extraHosts"`
}

type MountInfo struct {
	Source string `yaml:"source"`
	Target string `yaml:"target"`
}

type RunContainer struct {
	Name         string            `yaml:"name"`
	Image        string            `yaml:"image"`
	Replicas     int               `yaml:"replicas"`
	Env          map[string]string `yaml:"env,omitempty"`
	Mounts       []MountInfo       `yaml:"mounts,omitempty"`
	IPRangeStart string            `yaml:"iprangeStart,omitempty"`
	Cmd          []string          `yaml:"cmd,omitempty"`
}

type NetworkInfo struct {
	Name string `yaml:"name"`
	CIDR string `yaml:"cidr,omitempty"`
}

type CAInfo struct {
	Country           string   `yaml:"countryName"`
	Province          string   `yaml:"provinceName"`
	Locality          string   `yaml:"localityName"`
	Organization      string   `yaml:"organizationName"`
	OrganizationUnit  string   `yaml:"organizationalUnitName"`
	SANIPs            []string `yaml:"sanIP"`
	ServerCommon      string   `yaml:"serverCommonName,omitempty"`
	ServerFilesPrefix string   `yaml:"serverFilesPrefix"`
	ClientCommon      string   `yaml:"clientCommonName,omitempty"`
	ClientFilesPrefix string   `yaml:"clientFilesPrefix"`
	OutputPath        string   `yaml:"outputPath"`
}

type Deployment struct {
	Network                NetworkInfo    `yaml:"network"`
	Build                  ImageBuild     `yaml:"build,omitempty"`
	Run                    []RunContainer `yaml:"run,omitempty"`
	WithLocalCache         bool           `yaml:"withLocalCache"`
	DockerClientAPIVersion string         `yaml:"dockerClientApiVersion"`
	CA                     CAInfo         `yaml:"ca,omitempty"`
}

var serialNum int64 = 0

func GetCertificate(country, province, locality, org, orgUnit, common string, isCA bool, isClient bool) (cert *x509.Certificate) {
	serialNum = serialNum + 1
	cert = &x509.Certificate{
		SerialNumber: big.NewInt(serialNum),
		Subject: pkix.Name{
			Country:            []string{country},
			Province:           []string{province},
			Locality:           []string{locality},
			Organization:       []string{org},
			OrganizationalUnit: []string{orgUnit},
			CommonName:         common,
		},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().AddDate(1, 0, 0),
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
	}
	if isCA {
		cert.IsCA = true
		cert.KeyUsage = x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign | x509.KeyUsageCRLSign
		cert.BasicConstraintsValid = true
	} else {
		cert.KeyUsage = x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment
	}
	return
}

func GenerateCAFiles(caInfo *CAInfo) {
	if caInfo.Country == "" {
		return
	}

	caPrivKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	ca := GetCertificate(caInfo.Country, caInfo.Province, caInfo.Locality, caInfo.Organization, caInfo.OrganizationUnit, "CA", true, false)
	cacert, err := x509.CreateCertificate(rand.Reader, ca, ca, &caPrivKey.PublicKey, caPrivKey)
	if err != nil {
		panic(err)
	}

	certOut, _ := os.Create(path.Join(caInfo.OutputPath, "ca.crt"))
	pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: cacert})
	certOut.Close()

	if caInfo.ServerCommon != "" {
		serverKey, _ := rsa.GenerateKey(rand.Reader, 2048)
		serverCertTemplate := GetCertificate(caInfo.Country, caInfo.Province, caInfo.Locality, caInfo.Organization, caInfo.OrganizationUnit, caInfo.ServerCommon, false, false)
		fmt.Println(caInfo.SANIPs)
		if len(caInfo.SANIPs) != 0 {
			subjectAltNameIPs := []net.IP{}
			for _, ipStr := range caInfo.SANIPs {
				subjectAltNameIPs = append(subjectAltNameIPs, net.ParseIP(ipStr))
			}
			serverCertTemplate.IPAddresses = subjectAltNameIPs
		}
		serverCert, err := x509.CreateCertificate(rand.Reader, serverCertTemplate, ca, &serverKey.PublicKey, serverKey)
		if err != nil {
			panic(err)
		}

		serverCertOut, _ := os.Create(path.Join(caInfo.OutputPath, fmt.Sprintf("%s.crt", caInfo.ServerFilesPrefix)))
		pem.Encode(serverCertOut, &pem.Block{Type: "CERTIFICATE", Bytes: serverCert})
		serverCertOut.Close()

		serverKeyBytes := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(serverKey)})
		ioutil.WriteFile(path.Join(caInfo.OutputPath, fmt.Sprintf("%s.key", caInfo.ServerFilesPrefix)), serverKeyBytes, 0644)
	}

	if caInfo.ClientCommon != "" {
		clientKey, _ := rsa.GenerateKey(rand.Reader, 2048)
		clientCertTemplate := GetCertificate(caInfo.Country, caInfo.Province, caInfo.Locality, caInfo.Organization, caInfo.OrganizationUnit, caInfo.ClientCommon, false, true)
		clientCert, err := x509.CreateCertificate(rand.Reader, clientCertTemplate, ca, &clientKey.PublicKey, clientKey)
		if err != nil {
			panic(err)
		}

		clientCertOut, _ := os.Create(path.Join(caInfo.OutputPath, fmt.Sprintf("%s.crt", caInfo.ClientFilesPrefix)))
		pem.Encode(clientCertOut, &pem.Block{Type: "CERTIFICATE", Bytes: clientCert})
		clientCertOut.Close()

		clientKeyBytes := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(clientKey)})
		ioutil.WriteFile(path.Join(caInfo.OutputPath, fmt.Sprintf("%s.key", caInfo.ClientFilesPrefix)), clientKeyBytes, 0644)
	}
}

func GenerateCAFilesByScript() {
	cmd := exec.Command("bash", "generate_ca_files.sh")
	if err := cmd.Run(); err != nil {
		panic(err)
	}
	fmt.Println("Generated CA files for etcd-cluster")
}

func CreateOrGetNetwork(cli *client.Client, ctx context.Context, name, cidr string) string {
	networkCreateOptions := types.NetworkCreate{
		CheckDuplicate: true,
		IPAM: &networktypes.IPAM{
			Config: []networktypes.IPAMConfig{
				networktypes.IPAMConfig{Subnet: cidr},
			},
		},
	}
	if netCreateResp, err := cli.NetworkCreate(ctx, name, networkCreateOptions); err != nil {
		filterArgs := filterstypes.NewArgs()
		filterArgs.Add("name", name)
		networkListOptions := types.NetworkListOptions{Filters: filterArgs}
		if netResourceResp, err := cli.NetworkList(ctx, networkListOptions); err != nil {
			panic(err)
		} else {
			return netResourceResp[0].ID
		}
	} else {
		return netCreateResp.ID
	}
}

func BuildImage(cli *client.Client, ctx context.Context, srcPath, imageName, networkID string, withLocalCache bool) {
	fmt.Printf("Start to build image: %s\n", imageName)
	dockerfileName := "Dockerfile"
	dockerfileContent, err := ioutil.ReadFile(path.Join(srcPath, "Dockerfile"))
	if err != nil {
		panic(err)
	}
	if withLocalCache {
		modified := false
		dockerfileSlices := strings.Split(string(dockerfileContent), "\n")
		if strings.Contains(string(dockerfileContent), "yum") {
			dockerfileSlices = append(dockerfileSlices, "")
			copy(dockerfileSlices[2:], dockerfileSlices[1:])
			dockerfileSlices[1] = "RUN rm -f /etc/yum.repos.d/*repo && curl -o /etc/yum.repos.d/private.repo http://repo.local.io/private.repo"
			modified = true
		}
		if strings.Contains(string(dockerfileContent), "curl") {
			dockerfileSlices = append(dockerfileSlices, "")
			copy(dockerfileSlices[2:], dockerfileSlices[1:])
			dockerfileSlices[1] = "RUN echo 'insecure' >> /root/.curlrc"
			modified = true
		}
		if strings.Contains(string(dockerfileContent), "git") {
			index := -1
			withRun := false
			for i, s := range dockerfileSlices {
				if strings.Contains(s, "git clone") {
					index = i
					if strings.HasPrefix(s, "RUN") {
						withRun = true
					}
					break
				}
			}
			if index >= 0 {
				dockerfileSlices = append(dockerfileSlices, "")
				copy(dockerfileSlices[index+1:], dockerfileSlices[index:])
				if withRun {
					dockerfileSlices[index] = "RUN git config --global http.sslVerify false"
				} else {
					dockerfileSlices[index] = "\tgit config --global http.sslVerify false && \\"
				}
				modified = true
			}
		}
		if modified {
			dockerfileName = fmt.Sprintf("%s.dockerfile", imageName)
			dockerfilePath := path.Join(srcPath, dockerfileName)
			if err := ioutil.WriteFile(dockerfilePath, []byte(strings.Join(dockerfileSlices, "\n")), 0644); err != nil {
				panic(err)
			}
			defer func() {
				if err := os.Remove(dockerfilePath); err != nil {
					panic(err)
				}
			}()
		}
	}
	buildCtx, err := archive.TarWithOptions(srcPath, &archive.TarOptions{})
	if err != nil {
		panic(err)
	}
	buildOptions := types.ImageBuildOptions{
		Tags:        []string{imageName},
		NetworkMode: networkID,
		Dockerfile:  dockerfileName,
	}
	if os.Getenv("EXTRAHOSTS") != "" {
		buildOptions.ExtraHosts = strings.Split(os.Getenv("EXTRAHOSTS"), ",")
	}
	resp, err := cli.ImageBuild(ctx, buildCtx, buildOptions)
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()

	scanner := bufio.NewScanner(resp.Body)
	logLine := ""
	for scanner.Scan() {
		line := new(BuildImageLog)
		err := json.Unmarshal(scanner.Bytes(), line)
		if err != nil {
			panic(fmt.Errorf("Failed to parse log, since: %s. Raw bytes: %s", err, scanner.Bytes()))
		}

		if line.ErrorDetail != "" {
			logLine = strings.Replace(line.ErrorDetail, "\n", "", -1)
			panic(fmt.Errorf("Failed to build image, since %s", logLine))
		}

		if strings.Contains(line.Stream, "% ") {
			logLine += strings.Replace(line.Stream, "% ", "%% ", -1)
		} else {
			logLine += line.Stream
		}
		if !strings.Contains(line.Stream, "\n") {
			continue
		}
		fmt.Printf(logLine)
		logLine = ""
	}
}

func Deploy(cli *client.Client, ctx context.Context, networkName, networkID, name, image, ipRangeStart string, replicas int, env *map[string]string, mount *[]MountInfo, cmd *[]string) {
	envs := []string{}
	for k, v := range *env {
		envs = append(envs, fmt.Sprintf("%s=%s", k, v))
	}
	mounts := []mounttypes.Mount{}
	for _, k := range *mount {
		mounts = append(mounts, mounttypes.Mount{Type: "bind", Source: k.Source, Target: k.Target})
	}
	config := &containertypes.Config{Image: image, Env: envs}
	if len(*cmd) != 0 {
		config.Cmd = *cmd
	}
	hostConfig := &containertypes.HostConfig{Mounts: mounts}
	networkConfig := &networktypes.NetworkingConfig{
		EndpointsConfig: map[string]*networktypes.EndpointSettings{
			networkName: &networktypes.EndpointSettings{
				NetworkID: networkID,
				IPAMConfig: &networktypes.EndpointIPAMConfig{
					IPv4Address: "",
				},
			},
		},
	}
	iprange := net.ParseIP(ipRangeStart)
	ipA, ipB, ipC, ipD := iprange[12], iprange[13], iprange[14], iprange[15]
	ipD = ipD - 1
	for i := 0; i < replicas; i++ {
		containerName := fmt.Sprintf("%s-%d", name, i)
		config.Hostname = containerName
		ipD = ipD + 1
		networkConfig.EndpointsConfig[networkName].IPAMConfig.IPv4Address = fmt.Sprintf("%s", net.IPv4(ipA, ipB, ipC, ipD))
		container, err := cli.ContainerCreate(ctx, config, hostConfig, networkConfig, containerName)
		if err != nil {
			panic(err)
		}
		if err := cli.ContainerStart(ctx, container.ID, types.ContainerStartOptions{}); err != nil {
			panic(err)
		}
	}
}

func main() {
	fileContentBytes, err := ioutil.ReadFile("/deploy.yaml")
	if err != nil {
		panic(err)
	}
	var deploy Deployment
	err = yaml.Unmarshal(fileContentBytes, &deploy)
	if err != nil {
		panic(err)
	}

	//GenerateCAFiles(&deploy.CA)
	GenerateCAFilesByScript()

	cli, err := client.NewClientWithOpts(client.WithVersion(deploy.DockerClientAPIVersion))
	if err != nil {
		panic(err)
	}

	ctx := context.Background()
	networkID := CreateOrGetNetwork(cli, ctx, deploy.Network.Name, deploy.Network.CIDR)

	for _, bi := range deploy.Build.Images {
		BuildImage(cli, ctx, bi.Source, bi.Name, networkID, deploy.WithLocalCache)
	}

	for _, r := range deploy.Run {
		Deploy(cli, ctx, deploy.Network.Name, networkID, r.Name, r.Image, r.IPRangeStart, r.Replicas, &r.Env, &r.Mounts, &r.Cmd)
	}
}
