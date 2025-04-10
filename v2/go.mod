module github.com/chainreactors/gogo/v2

go 1.21

toolchain go1.24.2

require (
	github.com/M09ic/go-ntlmssp v0.0.0-20230312133735-dcccd454dfe0
	github.com/chainreactors/files v0.0.0-20240716182835-7884ee1e77f0
	github.com/chainreactors/fingers v1.0.1
	github.com/chainreactors/logs v0.0.0-20241115105204-6132e39f5261
	github.com/chainreactors/neutron v0.0.0-20250113061151-32771f256b1f
	github.com/chainreactors/parsers v0.0.0-20241107171801-3f8b998dedc1
	github.com/chainreactors/proxyclient v1.0.3-0.20250219180226-a25a0c9e6ac8
	github.com/chainreactors/utils v0.0.0-20250109082818-178eed97b7ab
	github.com/jessevdk/go-flags v1.6.1
	github.com/panjf2000/ants/v2 v2.9.1
	golang.org/x/net v0.23.0
	gopkg.in/yaml.v3 v3.0.1
)

require (
	github.com/Knetic/govaluate v3.0.0+incompatible // indirect
	github.com/asaskevich/govalidator v0.0.0-20230301143203-a9d515a09cc2 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/facebookincubator/nvdtools v0.1.5 // indirect
	github.com/go-dedup/megophone v0.0.0-20170830025436-f01be21026f5 // indirect
	github.com/go-dedup/simhash v0.0.0-20170904020510-9ecaca7b509c // indirect
	github.com/go-dedup/text v0.0.0-20170907015346-8bb1b95e3cb7 // indirect
	github.com/hashicorp/go-version v1.6.0 // indirect
	github.com/mozillazg/go-pinyin v0.20.0 // indirect
	github.com/riobard/go-bloom v0.0.0-20200614022211-cdc8013cb5b3 // indirect
	github.com/shadowsocks/go-shadowsocks2 v0.1.5 // indirect
	github.com/spaolacci/murmur3 v1.1.0 // indirect
	github.com/twmb/murmur3 v1.1.8 // indirect
	github.com/weppos/publicsuffix-go v0.15.1-0.20220329081811-9a40b608a236 // indirect
	golang.org/x/crypto v0.33.0 // indirect
	golang.org/x/sys v0.30.0 // indirect
	golang.org/x/text v0.14.0 // indirect
)

replace (
	golang.org/x/crypto => golang.org/x/crypto v0.0.0-20191205180655-e7c4368fe9dd
	golang.org/x/net => golang.org/x/net v0.0.0-20200202094626-16171245cfb2
	golang.org/x/sys => golang.org/x/sys v0.0.0-20200223170610-d5e6a3e2c0ae
	golang.org/x/text => golang.org/x/text v0.3.3
)
