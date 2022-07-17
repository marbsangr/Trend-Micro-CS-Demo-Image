pipeline {
  node {  
    stage ('Checkout') {
      git 'https://github.com/XeniaP/Trend-Micro-Smart-Check-Demo-Image.git'  
    }
    stage ('Docker build'){  
      docker.build('demo-app')  
    }
    stage ('Docker push'){
      docker.withRegistry('https://846753579733.dkr.ecr.us-east-1.amazonaws.com/tm-demo', 'ECR') {    
        docker.image('demo-app').push('latest')
      }
    } 
    stage ('Deep Security Smart Check scan'){ 
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
