echo "-------------------> BUILDING <--------------------";
bash /app/release/build.sh

echo "-------------------> PACKAGING <--------------------";
bash release/package.sh 

echo "-------------------> UNINSTALL OLD <--------------------";
kubectl krew update
kubectl krew uninstall debug-ward
