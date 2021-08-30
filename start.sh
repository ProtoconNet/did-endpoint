sampleFile="src/configs/samples.py"
cp $sampleFile ../_samples.py
rm $sampleFile
git pull
if [ -f "$sampleFile" ]; then
	echo "file exist"
	sed -e s/"127.0.0.1"/"mtm.securekim.com"/g $sampleFile > $sampleFile.tmp && mv $sampleFile.tmp $sampleFile
else
	echo "file not exist"
	cp ../_samples.py $sampleFile
fi
killall python3
python3 src/issuer.py&
python3 src/verifier.py&

