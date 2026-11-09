# Step
    1. Create clave ssh in pc client (código)
```shell
ssh-keygen -t ed25519 -f ~/.ssh/<name-key>
```
    2. Copy value public key in server in ~/.ssh/authorized_keys
```shell
echo "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIN7ZlAWVJn7jP/6e3mTWM308ypwHE3a8YJ6InAfEZWSX" >> ~/.ssh/authorized_keys
```
    3. Obter key public server ED25519
```shell
ssh-keyscan -t ed25519 -p 22 111.11.11.111
```
    4. Set value in .env
```env
XXX_PATH_SECRET_KEY="/Users/<nameUser>/.ssh/name_key_private"
XXX_PUBLIC_KEY_SERVER="ssh-ed25519 XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
XXX_HOST="<ip_server>"
XXX_USER=<user>
```
    5. If error in connect, set permission  in server for 
       1. chmod -R 700 ~/.ssh/
       2. chmod -R 600 ~/.ssh/authorized_keys
# Observer connection ssh
```shell
sudo journalctl -u ssh -n 50 --no-pager
```