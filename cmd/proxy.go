// Copyright © 2019 lpisces <iamalazyrat@gmail.com>
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.

package cmd

import (
	"fmt"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"os"
	"strings"
	"text/template"
)

type NginxData struct {
	SSL               bool
	HTTP2             bool
	HTTPRedirect      bool
	Port              string
	ServerNames       string
	ServerName        string
	SSLCertificate    string
	SSLCertificateKey string
	OriginHost        string
	OriginPort        string
	OriginProtocol    string
	CORS              bool
}

var nginxData NginxData
var viperProxy *viper.Viper = viper.New()
var temp string = `
upstream local_port_{{.OriginPort}}{
  server {{.OriginHost}}:{{.OriginPort}};
}

{{if ne .Port "80"}}
{{if .HTTPRedirect}}
server{
 listen 80;
 server_name {{.ServerNames}};
 rewrite ^/(.*) https://{{.ServerName}}{{if ne .Port "443"}}:{{.Port}}{{end}}/$1 redirect;
}
{{end}}
{{end}}

server {
  listen {{.Port}} {{if .SSL}}ssl{{end}} {{if .HTTP2}}http2{{end}};
  server_name {{.ServerNames}};

  client_max_body_size 8M;
  client_body_buffer_size 1024M;

	{{if .SSL}}
  ssl on;
  ssl_certificate {{.SSLCertificate}};
  ssl_certificate_key {{.SSLCertificateKey}};
  ssl_session_timeout 5m;
  ssl_protocols TLSv1.2 TLSv1.1 TLSv1;
  ssl_ciphers ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-SHA384:ECDHE-RSA-AES128-SHA256:ECDHE-RSA-AES256-SHA:ECDHE-RSA-AES128-SHA:DHE-RSA-AES256-SHA256:DHE-RSA-AES128-SHA256:DHE-RSA-AES256-SHA:DHE-RSA-AES128-SHA:ECDHE-RSA-DES-CBC3-SHA:EDH-RSA-DES-CBC3-SHA:AES256-GCM-SHA384:AES128-GCM-SHA256:AES256-SHA256:AES128-SHA256:AES256-SHA:AES128-SHA:DES-CBC3-SHA:HIGH:!aNULL:!eNULL:!EXPORT:!DES:!MD5:!PSK:!RC4;
  ssl_session_cache shared:SSL:10m;
  ssl_prefer_server_ciphers on;
	{{end}}
  location / {
		{{if .CORS}}
    # CORS
    add_header Access-Control-Allow-Origin *;
    add_header Access-Control-Allow-Methods 'GET, POST, OPTIONS, DELETE, PUT';
    add_header Access-Control-Allow-Headers 'DNT,X-Mx-ReqToken,Keep-Alive,User-Agent,X-Requested-With,If-Modified-Since,Cache-Control,Content-Type,Authorization';
    if ($request_method = 'OPTIONS') {
        return 204;
    }
		{{end}}

    proxy_set_header        Host $host:$server_port;
    proxy_set_header        X-Real-IP $remote_addr;
    proxy_set_header        X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header        X-Forwarded-Proto $scheme;

    # Fix the "It appears that your reverse proxy set up is broken" error.
    proxy_pass          {{.OriginProtocol}}://local_port_{{.OriginPort}};
    proxy_read_timeout  90;
    proxy_redirect      {{.OriginProtocol}}://local_port_{{.OriginPort}} {{if .SSL}}https{{else}}http{{end}}://{{.ServerName}};

    # Required for new HTTP-based CLI
    proxy_http_version 1.1;
    proxy_request_buffering off;
  }

  access_log  /var/log/nginx/{{.ServerName}}.access.log;
  error_log  /var/log/nginx/{{.ServerName}}.error.log;
}
`

// proxyCmd represents the proxy command
var proxyCmd = &cobra.Command{
	Use:   "proxy",
	Short: "Generate configuration for port proxy.",
	Long: `
http example:

./nginxc proxy \
	--ssl=false \
	--http2=false \
	--origin-host 127.0.0.1 \
	--origin-port 10000 \
	--origin-protocol http \
	--port 80 \
	--server-names "a.com b.com" \
	--cors \
	--output ./a.com.conf

https example:

./nginxc proxy \
	--ssl \
	--http2 \
	--origin-host 127.0.0.1 \
	--origin-port 10000 \
	--origin-protocol http \
	--port 443 \
	--server-names "a.com b.com" \
	--cors \
	--http-redirect \
	--ssl-certificate a.cer \
	--ssl-certificate-key a.key \
	--output ./a.com.conf
`,
	Run: func(cmd *cobra.Command, args []string) {

		nginxData = NginxData{
			SSL:               viperProxy.GetBool("ssl"),
			HTTP2:             viperProxy.GetBool("http2"),
			HTTPRedirect:      viperProxy.GetBool("http-redirect"),
			Port:              viperProxy.GetString("port"),
			ServerNames:       viperProxy.GetString("server-names"),
			ServerName:        strings.Split(viperProxy.GetString("server-names"), " ")[0],
			SSLCertificate:    viperProxy.GetString("ssl-certificate"),
			SSLCertificateKey: viperProxy.GetString("ssl-certificate-key"),
			OriginHost:        viperProxy.GetString("origin-host"),
			OriginPort:        viperProxy.GetString("origin-port"),
			OriginProtocol:    viperProxy.GetString("origin-protocol"),
			CORS:              viperProxy.GetBool("cors"),
		}

		if viperProxy.GetBool("debug") {
			fmt.Printf("%v\n", nginxData)
		}

		if nginxData.SSL && len(nginxData.SSLCertificate) == 0 && len(nginxData.SSLCertificateKey) == 0 {
			fmt.Printf("SSL Certificate & Key required.\n")
			os.Exit(1)
		}

		t := template.Must(template.New("nginx").Parse(temp))
		if len(viperProxy.GetString("output")) == 0 {
			err := t.Execute(os.Stdout, nginxData)
			if err != nil {
				fmt.Printf("%v", err)
				os.Exit(1)
			}
		} else {
			output, err := os.OpenFile(viperProxy.GetString("output"), os.O_RDWR|os.O_CREATE, 0755)
			if err != nil {
				fmt.Printf("%v", err)
				os.Exit(1)
			}

			err = t.Execute(output, nginxData)
			if err != nil {
				fmt.Printf("%v", err)
				os.Exit(1)
			}
		}
	},
}

func init() {
	rootCmd.AddCommand(proxyCmd)

	// debug
	proxyCmd.Flags().Bool("debug", false, "debug mode")
	viperProxy.BindPFlag("debug", proxyCmd.Flags().Lookup("debug"))

	// ssl
	proxyCmd.Flags().Bool("ssl", true, "enable ssl")
	viperProxy.BindPFlag("ssl", proxyCmd.Flags().Lookup("ssl"))

	// http2
	proxyCmd.Flags().Bool("http2", true, "enable http2")
	viperProxy.BindPFlag("http2", proxyCmd.Flags().Lookup("http2"))

	// port
	proxyCmd.Flags().String("port", "443", "listen port")
	viperProxy.BindPFlag("port", proxyCmd.Flags().Lookup("port"))

	// server name
	proxyCmd.Flags().String("server-names", "default_server", "server names")
	viperProxy.BindPFlag("server-names", proxyCmd.Flags().Lookup("server-names"))

	// ssl certificate
	proxyCmd.Flags().String("ssl-certificate", "", "ssl certificate")
	viperProxy.BindPFlag("ssl-certificate", proxyCmd.Flags().Lookup("ssl-certificate"))

	// ssl certificate key
	proxyCmd.Flags().String("ssl-certificate-key", "", "ssl certificate key")
	viperProxy.BindPFlag("ssl-certificate-key", proxyCmd.Flags().Lookup("ssl-certificate-key"))

	// origin host
	proxyCmd.Flags().String("origin-host", "127.0.0.1", "origin host")
	viperProxy.BindPFlag("origin-host", proxyCmd.Flags().Lookup("origin-host"))

	// origin port
	proxyCmd.Flags().String("origin-port", "10000", "origin port")
	viperProxy.BindPFlag("origin-port", proxyCmd.Flags().Lookup("origin-port"))

	// origin protocol
	proxyCmd.Flags().String("origin-protocol", "http", "origin protocol")
	viperProxy.BindPFlag("origin-protocol", proxyCmd.Flags().Lookup("origin-protocol"))

	// http redirect
	proxyCmd.Flags().Bool("http-redirect", false, "http request to be redirected to https")
	viperProxy.BindPFlag("http-redirect", proxyCmd.Flags().Lookup("http-redirect"))

	// enable CORS
	proxyCmd.Flags().Bool("cors", true, "enable CORS")
	viperProxy.BindPFlag("cors", proxyCmd.Flags().Lookup("cors"))

	// output
	proxyCmd.Flags().String("output", "", "save configuration file")
	viperProxy.BindPFlag("output", proxyCmd.Flags().Lookup("output"))
}
