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
      }
    }
    stage ('Docker push'){
      steps {
        docker.withRegistry('https://846753579733.dkr.ecr.us-east-1.amazonaws.com/tm-demo', 'ECR') {    
          docker.image('demo-app').push('latest')
        }
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
                smartcheckHost: "smartcheck.example.com",
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
