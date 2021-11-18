DIR="$( cd "$( dirname "$0" )" && pwd -P )"
cd $DIR
sampleFile="$DIR/src/configs/samples.py"
cp $sampleFile $DIR/../_samples.py
rm $sampleFile
git pull
if [ -f "$sampleFile" ]; then
        echo "file exist"
        sed -e s/"127.0.0.1"/"mtm.securekim.com"/g $sampleFile > $sampleFile.tmp && mv $sampleFile.tmp $sampleFile
else
        echo "file not exist"
        cp $DIR/../_samples.py $sampleFile
fi
killall python3
python3 $DIR/src/issuer.py&
python3 $DIR/src/verifier.py&