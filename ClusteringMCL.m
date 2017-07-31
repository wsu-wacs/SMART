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

% Data: Rows->Samples    Columns->Features
% Train Label: Rows->Samples Columns->0:Human 1:Robot
% Test Label: Rows->Samples Columns->0:Human 1:Bening Robot 2:Malicious Robots
% Clusters: Rows->Samples    Columns->Coresponding category
function [TP, FP, TN, FN, MM, MB, MH, BM, BB, BH]=ClusteringMCL(Train,Test)
%% Initializing
%Initial variables
Data=Train(:,1:end-1);
FeatureNumber=size(Data,2);
SampleNumber=size(Data,1);
Convergency=0;

%Prune Parameters
a=1;b=1;

%Convergency Parameter
Emax=10;%Number of Iterartion the energy does not reduce
%% Min-Max Normalization
Data=Data-repmat(min(Data),SampleNumber,1);
%Data=Data./repmat(max(Data),SampleNumber,1);
for i=1:FeatureNumber
    Divider=max(Data(:,i));
    if(Divider==0),continue,end
    Data(:,i)=Data(:,i)./Divider;
end

%% Similarity Matrix -> cosinus similarity(Ms)
%cosTheta(u,v) = dot(u,v)/(norm(u)*norm(v))
Similarity=zeros(SampleNumber);
for i=1:SampleNumber
    %nominator
    Temp=repmat(Data(i,:),SampleNumber,1).*Data;
    Temp=sum(Temp,2);
    %denominator
    Temp2=Data.*Data;
    Temp2=sqrt(sum(Temp2,2));
    Temp2=repmat(Temp2(i),SampleNumber,1).*Temp2;
    Temp=Temp./Temp2;
    
    Temp2=find(isnan(Temp));
    Temp2=[Temp2 find(Temp==inf)];
    Temp(Temp2)=0;
    
    Similarity(i,:)=Temp';
end

%% Adjacency Matrix->M adj
MAdjacency=Similarity;
Temp=ceil(SampleNumber/(2*ceil(sqrt(SampleNumber))));
Threshold=Temp*ceil(sqrt(SampleNumber));
Temp=sort(Similarity,2,'descend');
MAdjacency=(MAdjacency>=repmat(Temp(:,Threshold),1,SampleNumber));
clearvars Similarity

%% M input
MInput=MAdjacency./repmat(sum(MAdjacency),SampleNumber,1);
Temp=find(isnan(MInput));
Temp=[Temp find(MInput==inf)];
MInput(Temp)=0;
clearvars MAdjacency
%% Main Loop of MCL
PreviousEnergy=inf;
Counter=0;
MInputSampleNumber=SampleNumber;
ValidateSessions=1:SampleNumber; %Samples where are validated to be categorized and are not noises

while (Convergency==0)
    %Expand
    MInput=MInput*MInput;
    
    %Infalte
    MInput=((MInput).^2);

    %Prune
    for i=1:MInputSampleNumber
        %Pruning
        %PrunTreshould=a[sum(ci^.2)]^b
        PrunTreshould=a*power(sum(MInput(:,i).^2),b);
        MInput(find(MInput(:,i)<PrunTreshould),i)=0;
        
        %Column wise again
        Temp=sum(MInput(:,i));
        if(Temp>0),MInput(:,i)=MInput(:,i)./Temp;end
    end
    
    %Singletone filterning
    Temp=MInput;%Tries to check all elements except for the diagonal ones
    Temp2=zeros(MInputSampleNumber,1);%Tries to check diagonal elements
    for i=1:MInputSampleNumber
        Temp(i,i)=0;
        Temp2(i)=MInput(i,i);
    end
    Temp=find(sum(Temp+Temp',2)==0);
    if(numel(Temp)>0)
        Isolate=Temp(find(Temp2(Temp)==1));
        if(numel(Isolate)>0)
            MInput(:,Isolate)=[];
            MInput(Isolate,:)=[];
            MInputSampleNumber=MInputSampleNumber-numel(Isolate);
            ValidateSessions(Isolate)=[];
        end
    end

    %Convergency
    Maxs=max(MInput);
    Sqsums=sum(MInput.^2);
    Energy=max(Maxs-Sqsums);
    if(Energy>=PreviousEnergy || Counter>Emax)
        
            Convergency=1;
        
    else
        disp('Number of Iterations:')
        Counter=Counter+1;
        disp(Counter)
        PreviousEnergy=Energy;
        disp('Energy:')
        disp(Energy)
    end
end

%% Interpret Initial Clusters
Categories=unique(MInput,'rows');
CategoryIndex=zeros(SampleNumber,1);
Temp=zeros(MInputSampleNumber,1);
CategoryNumber=size(Categories,1);
for i=1:CategoryNumber
   Temp(find(sum(abs(MInput-repmat(Categories(i,:),MInputSampleNumber,1)),2)==0))=i;
end
CategoryIndex(ValidateSessions)=Temp;

%% Recognizing cluster centers based on average of features of their samples
Center=zeros(CategoryNumber,FeatureNumber+1);
for i=1:CategoryNumber
    Temp=find(CategoryIndex==i);
    Center(i,:)=sum(Train(Temp,:))/numel(Temp);
    Center(i,end)=i;
end

%% Diagnosis the test samples clusteres and categories
TestNumber=size(Test,1);
Label=zeros(TestNumber,1);
for i=1:TestNumber    
    %nominator
    Temp=repmat(Test(i,1:end-1),CategoryNumber,1).*Center(:,1:end-1);
    Temp=sum(Temp,2);
    %denominator
    Temp2=Center(:,1:end-1).*Center(:,1:end-1);
    Temp2=sqrt(sum(Temp2,2));
    Temp3=sqrt(sum(Test(i,1:end-1).*Test(i,1:end-1)));
    Temp2=repmat(Temp3,CategoryNumber,1).*Temp2;
    Temp=Temp./Temp2;
    
    Temp2=find(isnan(Temp));
    Temp2=[Temp2 find(Temp==inf)];
    Temp(Temp2)=0;
    
    Similarity=Temp;
    
    Temp=find(Similarity==max(Similarity));
    if(numel(Temp)==1)
        Label(i)=Center(Temp,end);
    else
        Label(i)=-1;%We recognize it as a noise 
    end
end

%% Convert category labels to Human 0/Bening 1/Malicious 2 labels
for i=1:CategoryNumber
    Temp=find(Label==i);
    if(numel(Temp)==0),continue,end
    Majority=mode(Test(Temp,end));
    Label(Temp)=Majority;
end

%% Comparison from robot and human detection aspect (1&2:Robot P/ 0:Human N)
% Computing TP, FP, TN, FN ->P:Robots' behaviour N:Humans' behaviour
TempT=(Test(:,end)>0);%1&2->1
TempL=Label>0;%1&2->1
TPCategory=find((TempT+TempL)==2);
TNCategory=find((TempT+TempL)==0);
FPCategory=find((TempT-TempL)==-1);
FNCategory=find((TempT-TempL)==1);

TP=numel(TPCategory);
TN=numel(TNCategory);
FP=numel(FPCategory);
FN=numel(FNCategory);
disp((TP+TN)/(TP+TN+FP+FN))

%% Analysis for Malicious detection by means of malicious Clusters
Temp=find(Label==2);%Recognizing samples which are diagnosed as malicious
MM=0;MB=0;MH=0;%Recognized malicious and be Malicious, Benign ,or Human
if(numel(Temp)~=0)
    Temp2=Test(Temp,end);
    MM=MM+numel(find(Temp2==2));
    MB=MB+numel(find(Temp2==1));
    MH=MH+numel(find(Temp2==0));
end

%% Analysis for Benign detection by means of Benign Clusters
Temp=find(Label==1);%Recognizing samples which are diagnosis as Benign
BM=0;BB=0;BH=0;%Recognized Bening and be Malicious, Benign ,or Human
if(numel(Temp)~=0)
    Temp2=Test(Temp,end);
    BM=BM+numel(find(Temp2==2));
    BB=BB+numel(find(Temp2==1));
    BH=BH+numel(find(Temp2==0));
end
end