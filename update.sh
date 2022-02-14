DIR="$( cd "$( dirname "$0" )" && pwd -P )"
cd $DIR
sampleFile="$DIR/src/configs/samples.py"
#Backup
mv $sampleFile $DIR/../_samples.py
git pull
#Restore
mv $DIR/../_samples.py $sampleFile
ps -ef | grep did-endpoint/src | grep -v grep | awk '{print $2}' | xargs kill -9 2>/dev/null
python3 $DIR/src/issuer.py&
python3 $DIR/src/verifier.py&
