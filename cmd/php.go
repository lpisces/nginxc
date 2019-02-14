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

type PHPData struct {
	SSL               bool
	HTTP2             bool
	HTTPRedirect      bool
	Port              string
	ServerNames       string
	ServerName        string
	SSLCertificate    string
	SSLCertificateKey string
	CORS              bool
	WebRoot           string
}

var phpData PHPData
var viperPhp *viper.Viper = viper.New()
var phpTemplate string = `
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

	index index.php index.html index.htm;
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

		try_files $uri $uri/ /index.php$is_args$args;
	}

	location ~ \.php$ {
		try_files $uri /index.php =404;
		fastcgi_pass php-fpm:9000;
		fastcgi_split_path_info ^(.+\.php)(/.+)$;
		fastcgi_index index.php;
		fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
		include fastcgi_params;
	}
}
`

// phpCmd represents the php command
var phpCmd = &cobra.Command{
	Use:   "php",
	Short: "Generate configuration for php site.",
	Long: `
http example:

./nginxc php \
	--ssl=false \
	--http2=false \
	--port 80 \
	--server-names "a.com b.com" \
	--cors \
	--output ./a.com.conf

https example:

./nginxc php \
	--ssl \
	--http2 \
	--port 443 \
	--server-names "a.com b.com" \
	--http-redirect \
	--ssl-certificate a.cer \
	--ssl-certificate-key a.key \
	--cors \
	--output ./a.com.conf
`,
	Run: func(cmd *cobra.Command, args []string) {
		phpData = PHPData{
			SSL:               viperPhp.GetBool("ssl"),
			HTTP2:             viperPhp.GetBool("http2"),
			HTTPRedirect:      viperPhp.GetBool("http-redirect"),
			Port:              viperPhp.GetString("port"),
			ServerNames:       viperPhp.GetString("server-names"),
			ServerName:        strings.Split(viperPhp.GetString("server-names"), " ")[0],
			SSLCertificate:    viperPhp.GetString("ssl-certificate"),
			SSLCertificateKey: viperPhp.GetString("ssl-certificate-key"),
			WebRoot:           viperPhp.GetString("web-root"),
			CORS:              viperProxy.GetBool("cors"),
		}

		if viperPhp.GetBool("debug") {
			fmt.Printf("%v\n", phpData)
		}

		if phpData.SSL && len(phpData.SSLCertificate) == 0 && len(phpData.SSLCertificateKey) == 0 {
			fmt.Printf("SSL Certificate & Key required.\n")
			os.Exit(1)
		}

		t := template.Must(template.New("static").Parse(staticTemplate))
		if len(viperPhp.GetString("output")) == 0 {
			err := t.Execute(os.Stdout, phpData)
			if err != nil {
				fmt.Printf("%v", err)
				os.Exit(1)
			}
		} else {
			output, err := os.OpenFile(viperPhp.GetString("output"), os.O_RDWR|os.O_CREATE, 0755)
			if err != nil {
				fmt.Printf("%v", err)
				os.Exit(1)
			}

			err = t.Execute(output, phpData)
			if err != nil {
				fmt.Printf("%v", err)
				os.Exit(1)
			}
		}
	},
}

func init() {
	rootCmd.AddCommand(phpCmd)

	// debug
	phpCmd.Flags().Bool("debug", false, "debug mode")
	viperPhp.BindPFlag("debug", phpCmd.Flags().Lookup("debug"))

	// ssl
	phpCmd.Flags().Bool("ssl", true, "enable ssl")
	viperPhp.BindPFlag("ssl", phpCmd.Flags().Lookup("ssl"))

	// http2
	phpCmd.Flags().Bool("http2", true, "enable http2")
	viperPhp.BindPFlag("http2", phpCmd.Flags().Lookup("http2"))

	// port
	phpCmd.Flags().String("port", "443", "listen port")
	viperPhp.BindPFlag("port", phpCmd.Flags().Lookup("port"))

	// server name
	phpCmd.Flags().String("server-names", "default_server", "server names")
	viperPhp.BindPFlag("server-names", phpCmd.Flags().Lookup("server-names"))

	// ssl certificate
	phpCmd.Flags().String("ssl-certificate", "", "ssl certificate")
	viperPhp.BindPFlag("ssl-certificate", phpCmd.Flags().Lookup("ssl-certificate"))

	// ssl certificate key
	phpCmd.Flags().String("ssl-certificate-key", "", "ssl certificate key")
	viperPhp.BindPFlag("ssl-certificate-key", phpCmd.Flags().Lookup("ssl-certificate-key"))

	// http redirect
	phpCmd.Flags().Bool("http-redirect", false, "http request to be redirected to https")
	viperPhp.BindPFlag("http-redirect", phpCmd.Flags().Lookup("http-redirect"))

	// root
	phpCmd.Flags().String("web-root", "/usr/share/nginx/html", "web root")
	viperPhp.BindPFlag("web-root", phpCmd.Flags().Lookup("web-root"))

	// enable CORS
	phpCmd.Flags().Bool("cors", true, "enable CORS")
	viperProxy.BindPFlag("cors", phpCmd.Flags().Lookup("cors"))

	// output
	phpCmd.Flags().String("output", "", "save configuration file")
	viperPhp.BindPFlag("output", phpCmd.Flags().Lookup("output"))
}
