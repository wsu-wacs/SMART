# A soft computing approach for benign and malicious web robot detection

This repository contains all the codes implemented for the experiments presented in the published paper "A soft computing approach for benign and malicious web robot detection".

## Getting Started

These instructions will get you a copy of the project up and running on your local machine for development and testing purposes.

### Prerequisites

All the codes in this repository are MATLAB files which can be executed by any version above R2015.

## Running the codes

According to the SMART flowchart (Figure 3 of paper), input is an access log file which should be prepared for first step (Session identification). The following explanations cover the pre processing steps implemented to convert the input access log files in a proper format.  
First, we execute a MATLAB script named ‘ImportLog.m’ to  read the data set (text file) and specify the necessary fields. The data sets used in this project have the Common Log Format (CLF) which looks something like this:
127.0.0.1 - frank [10/Oct/2000:13:55:36 -0700] "GET /apache_pb.gif HTTP/1.0" 200 2326

The lines below show the related codes of this script to specify the nine necessary field:
'''
    Space=find(line==' ');
    IP{i}=line(1:Space(1)-1);
    DateTime{i}=line(Space(3)+2:Space(4)-1);
    HttpMethod{i}=line(Space(5)+2:Space(6)-1);
    File{i}=line(Space(6)+1:Space(7)-1);
    ErrorCode{i}=line(Space(8)+1:Space(9)-1);
    DataVolume{i}=line(Space(9)+1:Space(10)-1);
    Referrer{i}=line(Space(10)+2:Space(11)-2);
    UserAgent{i}=line(Space(11)+1:end);
'''
The output is a .mat file in the same path of the input. It is worth mentioning that a file with a .mat extension contains MATLAB formatted data (the fields indicated above) and this data can be loaded from or written to this file by using the functions LOAD and SAVE, respectively. Also, the name of output file is similar to the name of input file plus the postfix ‘Converted.mat‘. 
In the next step, we execute a script called ‘Cleaning.m’. This script asks the user for the input file which have been produced in the previous step (.Converted’ file). The aim of this step is to:
 
1. Ascendingly order all requests based on their time.
2. Remove requests which have all identical fields (in some data sets, there are some completely similar requests which seem to have been duplicated and carry no useful information.)
3. Change all data to lower case for improving the performance of
later analysis.
4. Convert ‘NaN’ to the value 0 for some null fields.

Please notice that the following .m files are the functions used to identify the duplicated IPs, User-Agent strings, Error Code, Referrer, and Data transferred fields:
CheckDuplicatesUserAgent.m
CheckDuplicatesReferrer.m
CheckDuplicatesIP.m
CheckDuplicatesErrorCode.m
CheckDuplicatesDataVolume.m

The output of Cleaning.m is a .mat file with similar name of the input plus a postfix 'AndCleaned.mat'.
After this step, the data is ready for the Session identification. A function called SessionIdentifier (SessionIdentifier.m) tries to identify all the sessions according to the definitions explained in the paper (page. 132). Please note that a MATLAB script named ‘FeatureExtraction.m’ calls the SessionIdentifier function to first identify the sessions and then extract features (Table. 1 of the paper) for each session. Similarly, it asks the user to specify the input file (produced in the previous step with postfix ‘Cleaned’) and creates an output as an .mat file with ‘Sessions’ postfix in its name. For more information about the features extracted in this step, please refer to both Table 1 of the paper and the comments provided in FeatureExtraction.m. 
According to the SMART flowchart, after the pre-processing step, the initial features and sessions are ready to be used for feature selection, and clustering. To do so, we implement a script named SMART.m which contains the related codes, respectively. Similarly, the following explanations are based on the flowchart of SMART in the paper. 
First, we specify the packages used in K-fold cross validation, and create the test and training packages. The variable named FoldNumber (equals to 10)shows the number of folds while the array named Fold contains the extracted folds. 

-Order=randperm(DataNumber);
FoldSize=floor(DataNumber/FoldNumbers);
for i=1:FoldNumbers-1**
    start=1+(i-1).FoldSize;
    finish=start+FoldSize-1;
    Fold{i}=Order(start:finish);-
end
% These are the rest added to 10th Fold
Fold{FoldNumbers}=Order(finish+1:end);**

The following lines in the code show the arrays used to save the results of K-fold cross validation for the algorithms, i.e. SMART, NNRD, DBC_WRD.

%>>> Smart variables in k-fold
FinalThreshold=zeros(ThresholdNumber,FoldNumbers);
%Row->Threshold Column->Iteration
TPSmart=zeros(ThresholdNumber,FoldNumbers);
FPSmart=zeros(ThresholdNumber,FoldNumbers);
TNSmart=zeros(ThresholdNumber,FoldNumbers);
FNSmart=zeros(ThresholdNumber,FoldNumbers);
MMSmart=zeros(ThresholdNumber,FoldNumbers);
MBSmart=zeros(ThresholdNumber,FoldNumbers);
MHSmart=zeros(ThresholdNumber,FoldNumbers);
BMSmart=zeros(ThresholdNumber,FoldNumbers);
BBSmart=zeros(ThresholdNumber,FoldNumbers);
BHSmart=zeros(ThresholdNumber,FoldNumbers);
 
TotalVisitPersentage=zeros(FoldNumbers,FeatureNumber);
 
%>>> Competetive algorithm variables in k-fold
TPNNRD=zeros(FoldNumbers,1);
FPNNRD=zeros(FoldNumbers,1);
TNNNRD=zeros(FoldNumbers,1);
FNNNRD=zeros(FoldNumbers,1);
MMNNRD=zeros(FoldNumbers,1);
MBNNRD=zeros(FoldNumbers,1);
MHNNRD=zeros(FoldNumbers,1);
BMNNRD=zeros(FoldNumbers,1);
BBNNRD=zeros(FoldNumbers,1);
BHNNRD=zeros(FoldNumbers,1);
 
TPDBC_WRD=zeros(FoldNumbers,1);
FPDBC_WRD=zeros(FoldNumbers,1);
TNDBC_WRD=zeros(FoldNumbers,1);
FNDBC_WRD=zeros(FoldNumbers,1);


The arrays whose names start with TP, TN, FP, FN prefixes are the arrays used to save the results of equations (13) and (14) of the paper. The rest indicate the arrays utilized to save the results reported in Figures (7) and (8) of the paper. For instance, MBNNRD shows the number of malicious robots NNRD identifies as benign. The lines below indicate what are selected as Train and Test datasets for each iteration of 10-fold cross validation. 

In the following step, we call NNRD and DBC_WRD functions which implement the SOM Neural Network and DBSCAN algorithms according to the explanations of the paper. MATLAB files named NNRD.m and DBC_WRD.m indicate these functions.
In the next step, we use the function called FRSFiltering to filter the initial features and select the final ones. This function divides the input data into 10 packages and run a function named FAA separately on each package. FAA is the main function implementing the Fuzzy Rough Feature Selection Algorithm based on the definitions presented in subsection 3.2 of the paper. The FRSFiltering output shows how many times (in percent) each feature is selected as final for the 10 packages. The next for loop indicate how we identify the final attributes for each FRS_thre value. For more information, please refer to the subsection 4.2 of the paper.
Finally, for each FRS_thre value, we run the MCL clustering algorithm and compute the evaluation metrics.  

VisitPercentage=FRSFiltering(TrainFRSMCL,FeatureNumber);
TotalVisitPercentage(Iteration,:)=VisitPercentage;
for i=1:10
        SelectedFeature=find(VisitPercentage>=Threshold(i));
        if(numel(SelectedFeature)==0),break,end  
        FinalThreshold(i, Iteration)=Threshold(i);
        SelectedFeature=[SelectedFeature FeatureNumber];
        [TPSmart(i, Iteration), FPSmart(i, Iteration), TNSmart(i, Iteration), FNSmart(i, Iteration), MMSmart(i, Iteration),       MBSmart(i, Iteration), MHSmart(i, Iteration), BMSmart(i, Iteration), BBSmart(i, Iteration), BHSmart(i, Iteration)]=ClusteringMCL(TrainFRSMCL(:,SelectedFeature),Test(:,SelectedFeature));    
    end
end


Also, ClusteringMCL is the function written to implement the MCL clustering algorithm. 
Eventually, the rest indicates how we calculate the metrics (Jaccard and Rand Index) used in the Experiments Section of the paper.  


## Authors

Mahdieh Zabihimayvan∗, Reza Sadeghi, H. Nathan Rude, Derek Doran.
Department of Computer Science and Engineering, Kno.e.sis Research Center, Wright State University, Dayton, OH, USA.

## License

This program is distributed under the License on an "AS IS" BASIS, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE- see the [LICENSE.md](LICENSE.md) file for details.

## Acknowledgments

This project is based on work supported by the National Science Foundation (NSF) under Grant no. 1464104. Any opinions, findings, and conclusions or recommendations expressed in this material are those of the author(s) and do not necessarily reflect the views of the NSF.
