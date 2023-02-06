Try to locate /robots.txt , /crossdomain.xml /clientaccesspolicy.xml /sitemap.xml and /.well-known/security.txt /security.txt

Secrets https://github.com/eth0izzle/shhgit
DoS https://github.com/thesc1entist/j0lt
GobyVuls https://github.com/gobysec/GobyVuls
JWT - https://github.com/jasonwubz/weak-jwt
Nuclei templates - https://github.com/kankburhan/gampung || https://github.com/xm1k3/cent
paste - https://github.com/carlospolop/Pastos







web analyzer - https://t.me/shadow_group_tg/339
ssl analyzer - https://github.com/nabla-c0d3/sslyze
revwhoix https://github.com/Sybil-Scan/revwhoix
IP-Finder https://github.com/SecLab-CH/IP-Finder
cero https://github.com/glebarez/cero
dnsx - https://github.com/projectdiscovery/dnsx
gotator - https://github.com/Josue87/gotator
puredns https://github.com/d3mondev/puredns
security headers - https://github.com/santoru/shcheck
google dorks - https://github.com/darklotuskdb/sd-goo
nmap censys - https://github.com/censys/nmap-censys
zoomeye - https://github.com/mmpx12/zoomeye-cli
Lepus https://github.com/gfek/Lepus
jsubfinder https://github.com/ThreatUnkown/jsubfinder
subdomain-brute https://github.com/hazemeldoc/subdomain-brute
yusub https://github.com/justakazh/yusub/
subfinder https://github.com/projectdiscovery/subfinder
assetfinder https://github.com/tomnomnom/assetfinder
takeover - https://github.com/haccer/subjack
takeover - https://github.com/jakejarvis/subtake
takeover - https://github.com/LukaSikic/subzy
Shodan - https://github.com/SmoZy92/Shodomain
Shodan - https://github.com/s4hm4d/shodanidb
dofind https://github.com/kankburhan/dofind/
hakrevdns https://github.com/hakluke/hakrevdns
cariddi https://github.com/edoardottt/cariddi
mksub https://github.com/trickest/mksub
censys https://github.com/christophetd/censys-subdomain-finder
pdlist https://github.com/gnebbia/pdlist
hakip2host https://github.com/hakluke/hakip2host
crt https://github.com/Nickguitar/GoSub
ssl_scrape https://t.me/shadow_group_tg/484
asnmap - https://github.com/projectdiscovery/asnmap
tld brute https://github.com/Sybil-Scan/TLDbrute
tlsx https://github.com/projectdiscovery/tlsx
frogy -  https://github.com/iamthefrogy/frogy
unimap - https://t.me/shadow_group_tg/486
jfscan - https://t.me/c/1345592925/1361
knockknock -  https://github.com/harleo/knockknock
amass -  https://github.com/OWASP/Amass | amass enum -d vimeo.com | https://t.me/shadow_group_tg/302
Turbolist3r -  https://github.com/fleetcaptain/Turbolist3r
BBScan -  https://github.com/lijiejie/BBScan
cloud_enum -  https://github.com/initstring/cloud_enum
s3scanner - https://github.com/sa7mon/S3Scanner
s3-buckets-finder - https://github.com/gwen001/s3-buckets-finder
secrets -  https://github.com/reewardius/secrets
go-dork -  https://github.com/dwisiswant0/go-dork
masscan -  https://github.com/robertdavidgraham/masscan
gf patterns -  https://github.com/r00tkie/grep-pattern
Jira -  https://github.com/MayankPandey01/Jira-Lens - https://t.me/shadow_group_tg/460
Confluence - https://t.me/shadow_group_tg/672
Censys - https://t.me/shadow_group_tg/672
Agnee - https://github.com/R0X4R/Agnee
Waymore https://t.me/shadow_group_tg/643
Httpx - https://t.me/shadow_group_tg/467
Nmap - https://t.me/shadow_group_tg/465 | https://t.me/c/1345592925/152
PureDNS - https://t.me/shadow_group_tg/461
FGDS - https://t.me/shadow_group_tg/451
VHostBrute - https://t.me/shadow_group_tg/450
Admin Finder - https://t.me/shadow_group_tg/426
cdncheck - https://github.com/projectdiscovery/cdncheck
cdn - https://github.com/christophetd/CloudFlair
cdn - https://github.com/mrh0wl/Cloudmare
cdn - https://github.com/Dheerajmadhukar/Lilly
waf https://github.com/EnableSecurity/wafw00f
git https://github.com/tillson/git-hound
git https://github.com/nyancrimew/goop
JS - https://github.com/riza/linx
kxss - 
unfurl - 
cloud - https://github.com/jordanpotti/CloudScraper
cloud - https://github.com/0xsha/CloudBrute
MX - https://github.com/musana/mx-takeover
jexboss - https://github.com/joaomatosf/jexboss
log4shell - https://github.com/dinosn/hikvision | https://t.me/c/1345592925/1918
csp recon domains - https://t.me/c/1345592925/2193
git - https://github.com/deletescape/goop
extension - https://github.com/kabilan1290/grapX
akamai - https://github.com/war-and-code/akamai-arl-hack
uncover - https://github.com/projectdiscovery/uncover



Resolvers:
https://github.com/shelld3v/flydns
https://github.com/Sybil-Scan/getresolvers
https://github.com/vortexau/dnsvalidator


echo "Starting nuclei"  | notify -silent -provider telegram
echo hackerone.com | naabu -silent -pf ports.txt | httpx -silent > result.md
cat result.md | nuclei -t /root/nuclei-templates/ -silent > result
echo "Hourly scan result $(date +%F-%T)"  | notify -silent -provider telegram
curl -v -F "chat_id=$ID" -F document=@result.json https://api.telegram.org/bot$TOKEN/sendDocument

#fuzzing
bbFuzzing https://github.com/reewardius/bbFuzzing.txt
ffuf https://t.me/c/1345592925/886
ffuf https://t.me/shadow_group_tg/429
mkpath https://github.com/trickest/mkpath
gau https://github.com/lc/gau
waybackurls https://github.com/tomnomnom/waybackurls
x8 https://github.com/Sh1Yo/x8 | https://t.me/shadow_group_tg/447
chameleon https://github.com/iustin24/chameleon
crlfuzz https://github.com/dwisiswant0/crlfuzz
cors https://github.com/s0md3v/Corsy
cors https://github.com/Shivangx01b/CorsMe
web socket https://github.com/ambalabanov/cswsh-scanner/
apache path traversal - https://github.com/imhunterand/ApachSAL
nginx - https://github.com/stark0de/nginxpwner
fuzzing headers - https://github.com/root-tanishq/userefuzz
403 https://github.com/devploit/dontgo403
403 https://github.com/hanhanhanz/forothree
403 https://github.com/daffainfo/bypass-403
403 https://github.com/channyein1337/403-bypass
403 https://github.com/lobuhi/byp4xx
403 https://github.com/p0dalirius/ipsourcebypass
fuzz - https://github.com/projectdiscovery/fuzzing-templates
traversal - https://github.com/ethicalhackingplayground/tprox

#vulns

https://gitlab.com/shodan-public/nrich
https://github.com/s0md3v/Smap
https://github.com/projectdiscovery/nuclei
https://github.com/hktalent/scan4all
https://github.com/zan8in/afrog
https://github.com/chaitin/xray
https://github.com/reewardius/Shodan
https://github.com/m4ll0k/BBTz/blob/master/shodanfy.py
https://github.com/redhuntlabs/Hunt4Spring
https://github.com/knassar702/lorsrf - ssrf
https://github.com/KathanP19/gaussrf - ssrf
https://github.com/ksharinarayanan/SSRFire - ssrf
https://github.com/swisskyrepo/SSRFmap - ssrf
https://github.com/devanshbatham/OpenRedireX - openredirect
https://github.com/r0075h3ll/Oralyzer - openredirect
https://github.com/dubs3c/Injectus - openredirect
https://github.com/wfinn/redirex - openredirect
https://github.com/0xRadi/oredirecto - openredirect
https://github.com/defparam/smuggler - smuggler
https://github.com/BishopFox/h2csmuggler - smuggler
https://github.com/dolevf/graphql-cop - graphql
https://github.com/0xn0ne/weblogicScanner - weblogicscanner












#help

https://github.com/m4ll0k/BBTz/blob/master/swfpfinder.sh
https://github.com/m4ll0k/BBTz/blob/master/favihash.py - https://t.me/shadow_group_tg/90
https://github.com/devanshbatham/FavFreak
JWT - https://github.com/ticarpi/jwt_tool
Cookie - https://t.me/w3b_pwn/1716

#Notes

Сканируем не только хосты, но и их ИП (обязательно)
https://t.me/shadow_group_tg/275
site:groups.google.com "$COMPANY"
https://docs.google.com/presentation/d/1cMSRVlJJ5de6Pyv-09YgzOGS0OYrP6p7ggGl0f42wmw/mobilepresent#slide=id.p
https://www.youtube.com/watch?v=Pyb5IfQHxik
https://t.me/c/1345592925/1519




