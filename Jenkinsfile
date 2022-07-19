pipeline {
  agent any
  stages {  
    stage ('Checkout') {
      steps {
        git 'https://github.com/XeniaP/Trend-Micro-Smart-Check-Demo-Image.git'
      } 
    }
    stage ('Docker build'){  
      steps {
        sh 'docker build -t 846753579733.dkr.ecr.us-east-1.amazonaws.com/tm-demo:latest .'
        sh 'docker build -t 846753579733.dkr.ecr.us-east-1.amazonaws.com/tm-demo:latest .'
      }
    }
    stage ('Docker push'){
      steps {
        sh 'aws ecr get-login-password --region us-east-1 | docker login --username AWS --password-stdin 846753579733.dkr.ecr.us-east-1.amazonaws.com'
        sh 'docker push 846753579733.dkr.ecr.us-east-1.amazonaws.com/tm-demo:latest'
      }
    } 
    stage ('Deep Security Smart Check scan'){
      steps { 
        withCredentials([
          usernamePassword([
              credentialsId: "registry-auth",
              usernameVariable: "REGISTRY_USER",
              passwordVariable: "REGISTRY_PASSWORD",
          ])
        ]){
            smartcheckScan([
                imageName: "846753579733.dkr.ecr.us-east-1.amazonaws.com/tm-demo",
                smartcheckHost: "ec2-54-159-74-184.compute-1.amazonaws.com:31820",
                smartcheckCredentialsId: "smartcheck-auth",
                imagePullAuth: new groovy.json.JsonBuilder([
                    username: REGISTRY_USER,
                    password: REGISTRY_PASSWORD,
                ]).toString(),
            ])
        }
      }
    }
  }
}
