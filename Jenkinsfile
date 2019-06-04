pipeline {
agent any
 stages {
   stage('Checkout') {
     steps {
       git 'https://github.com/XeniaP/scExample.git'
     }
   }
   stage('Docker build') {
     steps {
       script {
         docker.build('test')
       }

     }
   }
   stage('ECR push') {
     steps {
       script {
         docker.withRegistry('https://786395520305.dkr.ecr.us-west-2.amazonws.com', 'ecr:us-west-2:xenia-ecr') {
           docker.image('test/keyfindin').push(env.IMAGETAG+'-'+env.BUILD_ID)}
         }

       }
     }
     stage('Smartcheck') {
       steps {
         script {
           $FLAG = sh([ script: 'python /home/scAPI.py', returnStdout: true ]).trim()
           if ($FLAG == '1') {
             sh 'docker tag test/keyfinding 786395520305.dkr.ecr.us-west-2.amazonaws.com/test/keyfinding'
             docker.withRegistry('https://786395520305.dkr.ecr.us-west-2.amazonws.com', 'ecr:us-west-2:xenia-ecr') {
               docker.image('786395520305.dkr.ecr.us-west-2.amazonaws.com/test/keyfinding').push(env.IMAGETAG+'-'+env.BUILD_ID) }
             }
               sh 'docker rmi $(docker images -q) -f 2> /dev/null'
             }

           }
         }
       }
       environment {
         IMAGETAG = 'tomcat'
         HIGH = '1'
         MEDIUM = '5'
         LOW = '5'
         NEGLIGIBLE = '5'
         UNKNOWN = '5'
         USER = 'administrator'
         PASSWORD = 'Trendmicr0!'
       }
     }
