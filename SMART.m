%                             Copyright (C) <2017> 
%                        Mahdieh ZabihiMayvan, Reza Sadeghi   
%     Department of Computer Science and Engineering, Kno.e.sis Research Center, 
%                Wright State University, Dayton, OH, USA
% 
%     This program is free software: you can redistribute it and/or modify
%     it under the terms of the GNU General Public License as published by
%     the Free Software Foundation, either version 3 of the License, or
%     any later version.
% 
%     This program is distributed under the License on an "AS IS" BASIS,
%     but WITHOUT ANY WARRANTY; without even the implied warranty of
%     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
%     GNU General Public License for more details.
% 
%     You should have received a copy of the GNU General Public License
%     along with this program.  If not, see <http://www.gnu.org/licenses/>.
%
%     Using this code or any associated file of this package in a publication, 
%     please CITE the related paper as below:
%
%     Zabihimayvan, Mahdieh, Reza Sadeghi, H. Nathan Rude, and Derek Doran. 
%     "A Soft Computing Approach for Benign and Malicious Web Robot Detection." 
%     Expert Systems with Applications 87 (2017) 129-140.

%     If you have any questions concerning the implementation of the code, 
%     please feel free to contact us via email addresses below:

%     Zabhimayvan.2@wright.edu, mahdieh@knoesis.org, sadeghi.2@wright.edu,
%     reza@knoesis.org.

% SMART & NNRD & DBC_WRD in 10-fold cross-validation

%% Load data
clc
clear
close all
pause(2)

[filename, pathname]=uigetfile({'*.*'},'Log file selector');
Path=[pathname filename];
load(Path)
Name=filename(1:length(filename)-4);
Name=[Name 'Final.mat'];
Name=[pathname '\' Name];

%% Initial variables
DataNumber=size(Feature,1);
FeatureNumber=size(Feature,2);
FoldNumbers=10;
Threshold=10:10:100;%Must be greater than zero and be integer
ThresholdNumber=numel(Threshold);
NNRDFeature=[4, 5, 6, 7, 9, 10, 16, 19, 20, 22, FeatureNumber];
%% K-fold cross-validation
%>>> Dividing sessions into 10 folds
Order=randperm(DataNumber);
FoldSize=floor(DataNumber/FoldNumbers);
for i=1:FoldNumbers-1
    start=1+(i-1)*FoldSize;
    finish=start+FoldSize-1;
    Fold{i}=Order(start:finish);
end
% These are the rest added to 10th Fold
Fold{FoldNumbers}=Order(finish+1:end);

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

TotalVisitPercentage=zeros(FoldNumbers,FeatureNumber);

%>>> variables of comparative algorithms in k-fold
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

for Iteration=1:10
    %>>> Creating the Train and Test  datasets
    switch Iteration
     case 1
          Train=[Fold{2:10}];
          Test=Fold{1};
     case 2
         Train=[Fold{1} Fold{3:10}];
         Test=Fold{2};
     case 3
         Train=[Fold{1:2} Fold{4:10}];
         Test=Fold{3};
     case 4
         Train=[Fold{1:3} Fold{5:10}];
         Test=Fold{4};
     case 5
         Train=[Fold{1:4} Fold{6:10}];
         Test=Fold{5};
     case 6
         Train=[Fold{1:5} Fold{7:10}];
         Test=Fold{6};
     case 7
         Train=[Fold{1:6} Fold{8:10}];
         Test=Fold{7};
     case 8
         Train=[Fold{1:7} Fold{9:10}];
         Test=Fold{8};
     case 9
         Train=[Fold{1:8} Fold{10}];
         Test=Fold{9};
     otherwise
         Train=[Fold{1:9}];
         Test=Fold{10};
    end
    
    %>>> Prepered package of sessions in form of Train and Test
    Train=Feature(Train,:);
    Test=Feature(Test,:);
    
    %>>> Running the comparative methods
    [TPNNRD(Iteration), FPNNRD(Iteration), TNNNRD(Iteration), FNNNRD(Iteration), MMNNRD(Iteration), MBNNRD(Iteration), MHNNRD(Iteration), BMNNRD(Iteration), BBNNRD(Iteration), BHNNRD(Iteration)]=NNRD(Train(:,NNRDFeature),Test(:,NNRDFeature));
    [~, ~, ~, ~, TPDBC_WRD(Iteration), FPDBC_WRD(Iteration), TNDBC_WRD(Iteration), FNDBC_WRD(Iteration)]=DBC_WRD(Train,Test);
    
    %>>> Smart method
    %Consider Robot sessions regardless of their types: so we temporarily
    %label all the sessions whose last feature (#30) equals to 1 and 2 as
    %robot. Finally, in SMART we recognize malicious ones based on the
    %value of FN.
    
    TrainFRSMCL=Train;
    TrainFRSMCL(:,end)=(TrainFRSMCL(:,end)>0);
    
    VisitPercentage=FRSFiltering(TrainFRSMCL,FeatureNumber);
    TotalVisitPercentage(Iteration,:)=VisitPercentage;
    
    for i=1:10
        SelectedFeature=find(VisitPercentage>=Threshold(i));
        if(numel(SelectedFeature)==0),break,end %No feature is reported
        FinalThreshold(i, Iteration)=Threshold(i);
        SelectedFeature=[SelectedFeature FeatureNumber]; %Add the label to the selected features
        [TPSmart(i, Iteration), FPSmart(i, Iteration), TNSmart(i, Iteration), FNSmart(i, Iteration), MMSmart(i, Iteration), MBSmart(i, Iteration), MHSmart(i, Iteration), BMSmart(i, Iteration), BBSmart(i, Iteration), BHSmart(i, Iteration)]=ClusteringMCL(TrainFRSMCL(:,SelectedFeature),Test(:,SelectedFeature));    
    end
end

% Recognizing number of threshold where all folds work on
MaxThreshold=0;
for i=1:ThresholdNumber
    Temp=find(FinalThreshold(i,:)==0);
    if(numel(Temp)>0),break,end
    MaxThreshold=MaxThreshold+1;
end

% Jaccard and RI computations
RIFoldsSmart=zeros(MaxThreshold,FoldNumbers);
JaccFoldsSmart=zeros(MaxThreshold,FoldNumbers);
for i=1:MaxThreshold
    for j=1:FoldNumbers
        if((TPSmart(i,j)+FPSmart(i,j)+TNSmart(i,j)+FNSmart(i,j))~=0)
            RIFoldsSmart(i,j)=(TPSmart(i,j)+TNSmart(i,j))/(TPSmart(i,j)+FPSmart(i,j)+TNSmart(i,j)+FNSmart(i,j));
        end
        if((TPSmart(i,j)+FPSmart(i,j)+FNSmart(i,j))~=0)
            JaccFoldsSmart(i,j)=TPSmart(i,j)/(TPSmart(i,j)+FPSmart(i,j)+FNSmart(i,j));
        end
    end
end

% Gathering the Accuracy and Jaccard for each threshold
FinalRISmart=sum(RIFoldsSmart,2)/FoldNumbers;
FinalJaccSmart=sum(JaccFoldsSmart,2)/FoldNumbers;

%>>> Computing Jaccard and Accuracy for comparative methods
RIFoldsNNRD=zeros(1,FoldNumbers);
RIFoldsDBC_WRD=zeros(1,FoldNumbers);

JaccFoldsNNRD=zeros(1,FoldNumbers);
JaccFoldsDBC_WRD=zeros(1,FoldNumbers);

for i=1:FoldNumbers
    if((TPNNRD(i)+FPNNRD(i)+TNNNRD(i)+FNNNRD(i))~=0)
        RIFoldsNNRD(i)=(TPNNRD(i)+TNNNRD(i))/(TPNNRD(i)+FPNNRD(i)+TNNNRD(i)+FNNNRD(i));RIFoldsNNRD(i)=(TPNNRD(i)+TNNNRD(i))/(TPNNRD(i)+FPNNRD(i)+TNNNRD(i)+FNNNRD(i));
    end
    if((TPDBC_WRD(i)+FPDBC_WRD(i)+TNDBC_WRD(i)+FNDBC_WRD(i))~=0)
        RIFoldsDBC_WRD(i)=(TPDBC_WRD(i)+TNDBC_WRD(i))/(TPDBC_WRD(i)+FPDBC_WRD(i)+TNDBC_WRD(i)+FNDBC_WRD(i));
    end
    if((TPNNRD(i)+FPNNRD(i)+FNNNRD(i))~=0)
        JaccFoldsNNRD(i)=TPNNRD(i)/(TPNNRD(i)+FPNNRD(i)+FNNNRD(i));
    end
    if((TPDBC_WRD(i)+FPDBC_WRD(i)+FNDBC_WRD(i))~=0)
        JaccFoldsDBC_WRD(i)=TPDBC_WRD(i)/(TPDBC_WRD(i)+FPDBC_WRD(i)+FNDBC_WRD(i));
    end
end

FinalRINNRD=sum(RIFoldsNNRD,2)/FoldNumbers;
FinalRIDBC_WRD=sum(RIFoldsDBC_WRD,2)/FoldNumbers;

FinalJaccNNRD=sum(JaccFoldsNNRD,2)/FoldNumbers;
FinalJaccDBC_WRD=sum(JaccFoldsDBC_WRD,2)/FoldNumbers;

%% Computational of total TP, TN, FP, FN
Temp=find(FinalRISmart==max(FinalRISmart),1,'first');
TPSmart=sum(TPSmart(Temp,:),2);
TNSmart=sum(TNSmart(Temp,:),2);
FPSmart=sum(FPSmart(Temp,:),2);
FNSmart=sum(FNSmart(Temp,:),2);

TPNNRD=sum(TPNNRD);
TNNNRD=sum(TNNNRD);
FPNNRD=sum(FPNNRD);
FNNNRD=sum(FNNNRD);

TPDBC_WRD=sum(TPDBC_WRD);
TNDBC_WRD=sum(TNDBC_WRD);
FPDBC_WRD=sum(FPDBC_WRD);
FNDBC_WRD=sum(FNDBC_WRD);

%% Analysis of detected malicious
MMSmart=sum(MMSmart(Temp,:));
MBSmart=sum(MBSmart(Temp,:));
MHSmart=sum(MHSmart(Temp,:));

MMNNRD=sum(MMNNRD);
MBNNRD=sum(MBNNRD);
MHNNRD=sum(MHNNRD);

%% Analysis of detected Benings
BMSmart=sum(BMSmart(Temp,:));
BBSmart=sum(BBSmart(Temp,:));
BHSmart=sum(BHSmart(Temp,:));

BMNNRD=sum(BMNNRD);
BBNNRD=sum(BBNNRD);
BHNNRD=sum(BHNNRD);

%% Analysis of Selected Features
FRS_Thre=Temp*10;
EliteFeatures=find((sum(TotalVisitPercentage)/FoldNumbers)>=FRS_Thre);
if(numel(EliteFeatures)==0)
    EliteFeatures=find((sum(TotalVisitPercentage)/FoldNumbers)>=0);
end
EliteFeaturesFRS_Thre=sum(TotalVisitPercentage(:,EliteFeatures))/FoldNumbers;

SelectedFeatureNumberInThresold=zeros(10,1);
for Temp=1:10
    SelectedFeatureNumberInThresold(Temp)=numel(find((sum(TotalVisitPercentage)/FoldNumbers)>=Temp*10));
end

save(Name,'Feature','FinalJaccDBC_WRD','FinalJaccNNRD','FinalJaccSmart','FinalRIDBC_WRD','FinalRINNRD','FinalRISmart','FNDBC_WRD', 'FNNNRD', 'FNSmart','FPDBC_WRD', 'FPNNRD', 'FPSmart','IP','MBNNRD', 'MBSmart', 'MHNNRD', 'MHSmart', 'MMNNRD', 'MMSmart','BBNNRD', 'BBSmart', 'BHNNRD', 'BHSmart', 'BMNNRD', 'BMSmart', 'SessionIndex','TNDBC_WRD', 'TNNNRD', 'TNSmart', 'TotalVisitPercentage', 'TPDBC_WRD', 'TPNNRD', 'TPSmart','UserAgent', 'EliteFeatures', 'EliteFeaturesFRS_Thre', 'FRS_Thre', 'SelectedFeatureNumberInThresold')