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


% NNRD: etection of malicious and non-malicious website visitors using unsupervised
% neural network learning
%***Unsupervised version***

% Train and Test: Row-> Sample Column->Features
% Train and Test are all data with their labels

function [TP, FP, TN, FN, MM, MB, MH, BM, BB, BH]=NNRD(Train,Test)
%% Min-Max Normalization of Train and Test->just features and not label one
%>>> Train
Data=Train(:,1:end-1);
[SampleNumber, FeatureNumber]=size(Data);
Data=Data-repmat(min(Data),SampleNumber,1);
%Data=Data./repmat(max(Data),SampleNumber,1);
for i=1:FeatureNumber
    Divider=max(Data(:,i));
    if(Divider==0),continue,end
    Data(:,i)=Data(:,i)./Divider;
end
Train(:,1:(end-1))=Data;

%>>> Test
Data=Test(:,1:end-1);
[SampleNumber, FeatureNumber]=size(Data);
Data=Data-repmat(min(Data),SampleNumber,1);
%Data=Data./repmat(max(Data),SampleNumber,1);
for i=1:FeatureNumber
    Divider=max(Data(:,i));
    if(Divider==0),continue,end
    Data(:,i)=Data(:,i)./Divider;
end
Test(:,1:(end-1))=Data;

clearvars Data i Divider
%% Train
% Create a Self-Organizing Map
dimension1 = 10;
dimension2 = 10;
net = selforgmap([dimension1 dimension2]);

% Train the Network
[net,~] = train(net,Train(:,1:end-1)');

%% Test
%TestNumber=size(Test,1);

[Index,~,~]=find(sim(net,Test(:,1:end-1)'));
%>>>
% Majority Label->what is the mojority of stimulated user agent for each
% neuron
%[Index,~,~]=find(sim(net,Train(:,1:end-1)'));
Majority=-ones(dimension1*dimension2,1);
for i=1:dimension1*dimension2
    Temp=find(Index==i);
    if(numel(Temp)==0),continue,end
    Label=Test(Temp,end);
    Majority(i)=mode(Label);
end
%>>>
% Comparison from robot and human detection aspect (1&2:Robot P/ 0:Human N)
TempM=(Majority(Index)>0);%1&2->1
TempT=(Test(:,end)>0);%1&2->1
TP=numel(find(TempM+TempT==2));
TN=numel(find(TempM+TempT==0));

FN=numel(find(TempM-TempT==-1));
FP=numel(find(TempM-TempT==1));


% Analysis for Malicious detection by means of malicious nerons
Temp=find(Majority==2);%Recognizing corresponding neurons for Malicious ones
MM=0;MB=0;MH=0;%Recognized malicious and be Malicious, Benign ,or Human
if(numel(Temp)~=0)
    for i=1:numel(Temp)
        Temp2=Test(find(Index==Temp(i)),end);
        MM=MM+numel(find(Temp2==2));
        MB=MB+numel(find(Temp2==1));
        MH=MH+numel(find(Temp2==0));
    end
end

% Analysis for Benign robots detection by means of benign nerons
Temp=find(Majority==1);%Recognizing corresponding neurons for benign ones
BM=0;BB=0;BH=0;%Recognized benign and be Malicious, Benign ,or Human
if(numel(Temp)~=0)
    for i=1:numel(Temp)
        Temp2=Test(find(Index==Temp(i)),end);
        BM=BM+numel(find(Temp2==2));
        BB=BB+numel(find(Temp2==1));
        BH=BH+numel(find(Temp2==0));
    end
end
end