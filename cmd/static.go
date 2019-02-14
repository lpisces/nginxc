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

type StaticData struct {
	SSL               bool
	HTTP2             bool
	HTTPRedirect      bool
	Port              string
	ServerNames       string
	ServerName        string
	SSLCertificate    string
	SSLCertificateKey string
	WebRoot           string
}

var staticData StaticData
var viperStatic *viper.Viper = viper.New()
var staticTemplate string = `
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
  index index.html index.htm;
  root {{.WebRoot}};

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

  expires off;
  charset utf-8;

  access_log  /var/log/nginx/{{.ServerName}}.access.log;
  error_log  /var/log/nginx/{{.ServerName}}.error.log;
}
`

// staticCmd represents the static command
var staticCmd = &cobra.Command{
	Use:   "static",
	Short: "Generate configuration for static web site.",
	Long: `
http example:

./nginxc static \
	--ssl=false \
	--http2=false \
	--port 80 \
	--server-names "a.com b.com" \
	--output ./a.com.conf

https example:

./nginxc static \
	--ssl \
	--http2 \
	--port 443 \
	--server-names "a.com b.com" \
	--http-redirect \
	--ssl-certificate a.cer \
	--ssl-certificate-key a.key \
	--output ./a.com.conf
`,
	Run: func(cmd *cobra.Command, args []string) {
		staticData = StaticData{
			SSL:               viperStatic.GetBool("ssl"),
			HTTP2:             viperStatic.GetBool("http2"),
			HTTPRedirect:      viperStatic.GetBool("http-redirect"),
			Port:              viperStatic.GetString("port"),
			ServerNames:       viperStatic.GetString("server-names"),
			ServerName:        strings.Split(viperStatic.GetString("server-names"), " ")[0],
			SSLCertificate:    viperStatic.GetString("ssl-certificate"),
			SSLCertificateKey: viperStatic.GetString("ssl-certificate-key"),
			WebRoot:           viperStatic.GetString("web-root"),
		}

		if viperStatic.GetBool("debug") {
			fmt.Printf("%v\n", staticData)
		}

		if staticData.SSL && len(staticData.SSLCertificate) == 0 && len(staticData.SSLCertificateKey) == 0 {
			fmt.Printf("SSL Certificate & Key required.\n")
			os.Exit(1)
		}

		t := template.Must(template.New("static").Parse(staticTemplate))
		if len(viperStatic.GetString("output")) == 0 {
			err := t.Execute(os.Stdout, staticData)
			if err != nil {
				fmt.Printf("%v", err)
				os.Exit(1)
			}
		} else {
			output, err := os.OpenFile(viperStatic.GetString("output"), os.O_RDWR|os.O_CREATE, 0755)
			if err != nil {
				fmt.Printf("%v", err)
				os.Exit(1)
			}

			err = t.Execute(output, staticData)
			if err != nil {
				fmt.Printf("%v", err)
				os.Exit(1)
			}
		}
	},
}

func init() {
	rootCmd.AddCommand(staticCmd)

	// debug
	staticCmd.Flags().Bool("debug", false, "debug mode")
	viperStatic.BindPFlag("debug", staticCmd.Flags().Lookup("debug"))

	// ssl
	staticCmd.Flags().Bool("ssl", true, "enable ssl")
	viperStatic.BindPFlag("ssl", staticCmd.Flags().Lookup("ssl"))

	// http2
	staticCmd.Flags().Bool("http2", true, "enable http2")
	viperStatic.BindPFlag("http2", staticCmd.Flags().Lookup("http2"))

	// port
	staticCmd.Flags().String("port", "443", "listen port")
	viperStatic.BindPFlag("port", staticCmd.Flags().Lookup("port"))

	// server name
	staticCmd.Flags().String("server-names", "default_server", "server names")
	viperStatic.BindPFlag("server-names", staticCmd.Flags().Lookup("server-names"))

	// ssl certificate
	staticCmd.Flags().String("ssl-certificate", "", "ssl certificate")
	viperStatic.BindPFlag("ssl-certificate", staticCmd.Flags().Lookup("ssl-certificate"))

	// ssl certificate key
	staticCmd.Flags().String("ssl-certificate-key", "", "ssl certificate key")
	viperStatic.BindPFlag("ssl-certificate-key", staticCmd.Flags().Lookup("ssl-certificate-key"))

	// http redirect
	staticCmd.Flags().Bool("http-redirect", false, "http request to be redirected to https")
	viperStatic.BindPFlag("http-redirect", staticCmd.Flags().Lookup("http-redirect"))

	// root
	staticCmd.Flags().String("web-root", "/usr/share/nginx/html", "web root")
	viperStatic.BindPFlag("web-root", staticCmd.Flags().Lookup("web-root"))

	// output
	staticCmd.Flags().String("output", "", "save configuration file")
	viperStatic.BindPFlag("output", staticCmd.Flags().Lookup("output"))
}
