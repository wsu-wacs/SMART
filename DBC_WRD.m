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


% DBC_WRD: Density Based Clustering for Web Robot Detection, Papers of
% Mahdieh in 2014

% Train and Test: Row-> Sample Column->Features
% Train and Test are all data with their labels

function [TPCategory, TNCategory, FPCategory, FNCategory, TP, FP, TN, FN]=DBC_WRD(Train,Test)
%% Initial variables
DataNumber=size(Train,1);
FeatureNumber=size(Train,2);

%DBSCAN parameters
epsilon=.9;
MinPts=6;

%Consider Robot ones regardless their types: convert 1&2->1
Train(:,end)=(Train(:,end)>0);
Test(:,end)=(Test(:,end)>0);

%% T-test for all features
TScore=zeros(FeatureNumber-1,1);

%>>>Feature(:,end)-> Robot:1 Human:0
RobotGroup=find(Train(:,end)==1);
HumanGroup=find(Train(:,end)==0);
RobotNumber=numel(RobotGroup);
HumanNumber=numel(HumanGroup);

for i=1:FeatureNumber-1
    if(sum(Train(:,i)-repmat(Train(1,i),DataNumber,1))==0),continue,end%Identical items should be skipped
    TScore(i)=abs(mean(Train(RobotGroup,i))-mean(Train(HumanGroup,i)))/sqrt((var(Train(RobotGroup,i))/RobotNumber)+(var(Train(HumanGroup,i))/HumanNumber));
end
disp(TScore)

%% Selection features based on Tscores
TScoreMax=floor(max(TScore));
Temp=zeros(TScoreMax,1);
for i=1:TScoreMax
    Temp(i)=sum(TScore>=i);
end
Temp2=zeros(size(Temp));
for i=2:TScoreMax-1
    Temp2(i)=Temp(i-1)-Temp(i+1);
end
SelectedTScore=find(Temp2==max(Temp2),1,'first');

SelectedFeatures=find(TScore>=SelectedTScore);
SelectedFeatures=[SelectedFeatures; FeatureNumber];

%% Clustering
[TPCategory, TNCategory, FPCategory, FNCategory, TP, FP, TN, FN]=DBSCAN(Train(:,SelectedFeatures),Test(:,SelectedFeatures),epsilon,MinPts);

end
