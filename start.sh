DIR="$( cd "$( dirname "$0" )" && pwd -P )"
cd $DIR
sampleFile="$DIR/src/configs/samples.py"
#Backup
mv $sampleFile $DIR/../_samples.py
git pull
#Restore
mv $DIR/../_samples.py $sampleFile
killall python3
python3 $DIR/src/issuer.py&
python3 $DIR/src/verifier.py&
